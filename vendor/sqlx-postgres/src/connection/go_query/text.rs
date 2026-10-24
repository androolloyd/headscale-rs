// Native text conversion adapts pgx v5.10.0 pgtype codecs and values.go.
// Copyright (c) 2013-2021 Jack Christensen. MIT terms: LICENSE-GO-PGX.

//! Convert SQLx's owned binary argument buffer into native pgx text inputs.

use crate::error::Error;
use crate::type_info::{PgType, PgTypeKind};
use crate::types::Oid;
use crate::PgTypeInfo;

pub(super) fn take<'a>(input: &mut &'a [u8], count: usize) -> Result<&'a [u8], Error> {
    let value = input
        .get(..count)
        .ok_or_else(|| err_protocol!("short native query argument"))?;
    *input = &input[count..];
    Ok(value)
}

fn integer<const N: usize>(input: &[u8]) -> Result<[u8; N], Error> {
    input
        .try_into()
        .map_err(|_| err_protocol!("invalid native query argument width"))
}

fn utf8(input: &[u8]) -> Result<String, Error> {
    std::str::from_utf8(input)
        .map(str::to_owned)
        .map_err(Error::protocol)
}

fn float(value: f64) -> String {
    if value.is_nan() {
        "NaN".to_owned()
    } else if value == f64::INFINITY {
        "+Inf".to_owned()
    } else if value == f64::NEG_INFINITY {
        "-Inf".to_owned()
    } else {
        value.to_string()
    }
}

fn civil(days: i64) -> (String, bool) {
    // Gregorian calendar arithmetic; the PostgreSQL epoch is 2000-01-01.
    let z = days + 10_957 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let bc = year <= 0;
    if bc {
        year = 1 - year;
    }
    (format!("{year:04}-{month:02}-{day:02}"), bc)
}

fn clock(micros: i64, fixed_fraction: bool) -> Result<String, Error> {
    if !(0..=86_400_000_000).contains(&micros) {
        return Err(err_protocol!("invalid native time argument"));
    }
    let seconds = micros / 1_000_000;
    let mut output = format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    );
    if fixed_fraction || micros % 1_000_000 != 0 {
        let fraction = format!("{:06}", micros % 1_000_000);
        output.push('.');
        output.push_str(if fixed_fraction {
            &fraction
        } else {
            fraction.trim_end_matches('0')
        });
    }
    Ok(output)
}

fn timestamp(input: &[u8], timezone: bool) -> Result<String, Error> {
    let micros = i64::from_be_bytes(integer(input)?);
    if micros == i64::MAX {
        return Ok("infinity".to_owned());
    }
    if micros == i64::MIN {
        return Ok("-infinity".to_owned());
    }
    let (date, bc) = civil(micros.div_euclid(86_400_000_000));
    Ok(format!(
        "{date} {}{}{}",
        clock(micros.rem_euclid(86_400_000_000), false)?,
        if timezone { "Z" } else { "" },
        if bc { " BC" } else { "" }
    ))
}

fn numeric(mut input: &[u8]) -> Result<String, Error> {
    let count = usize::from(u16::from_be_bytes(integer(take(&mut input, 2)?)?));
    let weight = i16::from_be_bytes(integer(take(&mut input, 2)?)?);
    let sign = u16::from_be_bytes(integer(take(&mut input, 2)?)?);
    let scale = i16::from_be_bytes(integer(take(&mut input, 2)?)?);
    match sign {
        0xc000 => return Ok("NaN".to_owned()),
        0xd000 => return Ok("Infinity".to_owned()),
        0xf000 => return Ok("-Infinity".to_owned()),
        0 | 0x4000 => {}
        _ => return Err(err_protocol!("invalid native numeric sign")),
    }
    if input.len() / 2 != count || input.len() % 2 != 0 {
        return Err(err_protocol!("invalid native numeric length"));
    }
    if count == 0 {
        // pgx decodes a zero-digit numeric as Int=0, Exp=0, regardless of
        // dscale. Do not fabricate fractional zeros absent from that value.
        return Ok("0".to_owned());
    }
    let mut digits = String::new();
    for _ in 0..count {
        let digit = u16::from_be_bytes(integer(take(&mut input, 2)?)?);
        if digit >= 10_000 {
            return Err(err_protocol!("invalid native numeric digit"));
        }
        digits.push_str(&format!("{digit:04}"));
    }
    let position = (i32::from(weight) + 1) * 4;
    let (mut whole, mut fraction) = if position <= 0 {
        (
            "0".to_owned(),
            "0".repeat(usize::try_from(-position).map_err(Error::protocol)?) + &digits,
        )
    } else {
        let position = usize::try_from(position).map_err(Error::protocol)?;
        if position >= digits.len() {
            (
                digits.clone() + &"0".repeat(position - digits.len()),
                String::new(),
            )
        } else {
            (digits[..position].to_owned(), digits[position..].to_owned())
        }
    };
    whole = whole.trim_start_matches('0').to_owned();
    if whole.is_empty() {
        whole.push('0');
    }
    if scale > 0 {
        let scale = scale as usize;
        if fraction.len() < scale {
            fraction.push_str(&"0".repeat(scale - fraction.len()));
        }
        fraction.truncate(scale);
    }
    let negative = sign == 0x4000 && (whole != "0" || fraction.bytes().any(|byte| byte != b'0'));
    Ok(format!(
        "{}{}{}{}",
        if negative { "-" } else { "" },
        whole,
        if fraction.is_empty() { "" } else { "." },
        fraction
    ))
}

fn quoted_array(value: &str) -> String {
    let space = |byte: u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c');
    if !value.is_empty()
        && !value.eq_ignore_ascii_case("null")
        && !value.as_bytes().first().copied().is_some_and(space)
        && !value.as_bytes().last().copied().is_some_and(space)
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'{' | b'}' | b',' | b'"' | b'\\'))
    {
        return value.to_owned();
    }
    let mut output = String::from("\"");
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            output.push('\\');
        }
        output.push(character);
    }
    output.push('"');
    output
}

fn array(mut input: &[u8], element: &PgTypeInfo, depth: usize) -> Result<String, Error> {
    let dimensions = i32::from_be_bytes(integer(take(&mut input, 4)?)?);
    let _flags = take(&mut input, 4)?;
    let _oid = take(&mut input, 4)?;
    if !(0..=6).contains(&dimensions) {
        return Err(err_protocol!("invalid native array dimensions"));
    }
    if dimensions == 0 {
        if !input.is_empty() {
            return Err(err_protocol!("trailing native array data"));
        }
        return Ok("{}".to_owned());
    }
    let mut shape = Vec::new();
    let mut total = 1_usize;
    let mut prefix = String::new();
    let mut explicit_bounds = false;
    for _ in 0..dimensions {
        let length = i32::from_be_bytes(integer(take(&mut input, 4)?)?);
        let lower = i32::from_be_bytes(integer(take(&mut input, 4)?)?);
        let size = usize::try_from(length).map_err(Error::protocol)?;
        total = total
            .checked_mul(size)
            .ok_or_else(|| err_protocol!("native array size overflow"))?;
        shape.push(size);
        explicit_bounds |= lower != 1;
        prefix.push_str(&format!(
            "[{}:{}]",
            lower,
            i64::from(lower) + i64::from(length) - 1
        ));
    }
    if total == 0 {
        // pgx emits {} before dimensions for any zero-cardinality shape.
        // Otherwise [i32::MAX, 0] would expand a tiny input into billions of
        // empty subarrays despite the payload-length check below.
        if !input.is_empty() {
            return Err(err_protocol!("trailing native array data"));
        }
        return Ok("{}".to_owned());
    }
    if total > input.len() / 4 {
        return Err(err_protocol!("short native array data"));
    }
    let mut values = Vec::with_capacity(total);
    for _ in 0..total {
        let length = i32::from_be_bytes(integer(take(&mut input, 4)?)?);
        if length == -1 {
            values.push("NULL".to_owned());
        } else {
            let length = usize::try_from(length).map_err(Error::protocol)?;
            values.push(quoted_array(&value(
                take(&mut input, length)?,
                element,
                depth + 1,
            )?));
        }
    }
    if !input.is_empty() {
        return Err(err_protocol!("trailing native array data"));
    }
    fn render(shape: &[usize], values: &[String], index: &mut usize, output: &mut String) {
        output.push('{');
        for offset in 0..shape[0] {
            if offset != 0 {
                output.push(',');
            }
            if shape.len() > 1 {
                render(&shape[1..], values, index, output);
            } else {
                output.push_str(&values[*index]);
                *index += 1;
            }
        }
        output.push('}');
    }
    let mut output = if explicit_bounds {
        prefix + "="
    } else {
        String::new()
    };
    render(&shape, &values, &mut 0, &mut output);
    Ok(output)
}

pub(super) fn value(input: &[u8], ty: &PgTypeInfo, depth: usize) -> Result<String, Error> {
    if depth > 32 {
        return Err(err_protocol!("native argument type nesting exceeds 32"));
    }
    if let Some(element) = ty.0.try_array_element() {
        return array(input, &element, depth);
    }
    Ok(match &ty.0 {
        PgType::Bool => match input {
            [0] => "f".to_owned(),
            [1] => "t".to_owned(),
            _ => return Err(err_protocol!("invalid native boolean argument")),
        },
        PgType::Int2 => i16::from_be_bytes(integer(input)?).to_string(),
        PgType::Int4 => i32::from_be_bytes(integer(input)?).to_string(),
        PgType::Int8 => i64::from_be_bytes(integer(input)?).to_string(),
        PgType::Oid => u32::from_be_bytes(integer(input)?).to_string(),
        PgType::Float4 => {
            let value = f32::from_be_bytes(integer(input)?);
            if value.is_finite() {
                value.to_string()
            } else {
                float(f64::from(value))
            }
        }
        PgType::Float8 => float(f64::from_be_bytes(integer(input)?)),
        PgType::Text
        | PgType::Varchar
        | PgType::Bpchar
        | PgType::Name
        | PgType::Unknown
        | PgType::Json => utf8(input)?,
        PgType::Jsonb | PgType::Jsonpath => {
            if input.first() != Some(&1) {
                return Err(err_protocol!("invalid native JSON format version"));
            }
            utf8(&input[1..])?
        }
        PgType::Bytea => format!("\\x{}", hex::encode(input)),
        PgType::Char => {
            if input.len() != 1 {
                return Err(err_protocol!("invalid native char argument"));
            }
            utf8(input)?
        }
        PgType::Uuid => {
            let data: [u8; 16] = integer(input)?;
            let hex = hex::encode(data);
            format!(
                "{}-{}-{}-{}-{}",
                &hex[..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..]
            )
        }
        PgType::Numeric => numeric(input)?,
        PgType::Date => {
            let days = i32::from_be_bytes(integer(input)?);
            if days == i32::MAX {
                "infinity".to_owned()
            } else if days == i32::MIN {
                "-infinity".to_owned()
            } else {
                let (date, bc) = civil(i64::from(days));
                date + if bc { " BC" } else { "" }
            }
        }
        PgType::Timestamp => timestamp(input, false)?,
        PgType::Timestamptz => timestamp(input, true)?,
        PgType::Time => clock(i64::from_be_bytes(integer(input)?), true)?,
        PgType::Interval => {
            let mut input = input;
            let micros = i64::from_be_bytes(integer(take(&mut input, 8)?)?);
            let days = i32::from_be_bytes(integer(take(&mut input, 4)?)?);
            let months = i32::from_be_bytes(integer(take(&mut input, 4)?)?);
            if !input.is_empty() {
                return Err(err_protocol!("trailing native interval data"));
            }
            let mut output = String::new();
            if months != 0 {
                output.push_str(&format!("{months} mon "));
            }
            if days != 0 {
                output.push_str(&format!("{days} day "));
            }
            // Preserve Go's signed-integer arithmetic even at MinInt64.
            let magnitude = if micros < 0 {
                output.push('-');
                micros.wrapping_neg()
            } else {
                micros
            };
            output.push_str(&format!(
                "{:02}:{:02}:{:02}",
                magnitude / 3_600_000_000,
                magnitude % 3_600_000_000 / 60_000_000,
                magnitude % 60_000_000 / 1_000_000
            ));
            if magnitude % 1_000_000 != 0 {
                output.push_str(&format!(".{:06}", magnitude % 1_000_000));
            }
            output
        }
        PgType::Inet | PgType::Cidr => {
            if input.len() < 4 {
                return Err(err_protocol!("short native network argument"));
            }
            let address = match (input[0], input[3], &input[4..]) {
                (2, 4, bytes) if bytes.len() == 4 && input[1] <= 32 => {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(integer::<4>(bytes)?))
                }
                (3, 16, bytes) if bytes.len() == 16 && input[1] <= 128 => {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(integer::<16>(bytes)?))
                }
                _ => return Err(err_protocol!("invalid native network argument")),
            };
            format!("{address}/{}", input[1])
        }
        PgType::Custom(custom) => match &custom.kind {
            PgTypeKind::Domain(base) => value(input, base, depth + 1)?,
            PgTypeKind::Enum(_) => utf8(input)?,
            _ => return Err(err_protocol!("unsupported native text argument type")),
        },
        PgType::DeclareWithOid(oid) => {
            let ty = PgTypeInfo::try_from_oid(Oid(oid.0))
                .ok_or_else(|| err_protocol!("unregistered native text argument type"))?;
            value(input, &ty, depth + 1)?
        }
        PgType::DeclareWithName(_) => {
            let text = utf8(input)?;
            if text.contains('\0') {
                return Err(err_protocol!("unregistered native text argument codec"));
            }
            text
        }
        _ => return Err(err_protocol!("unsupported native text argument type")),
    })
}
