//! Go's JSON encoder honors protobuf JSON tags; its YAML encoder reflects Go
//! struct fields instead. Keep that distinct wire contract explicit here.

use serde::{Serialize, Serializer, ser::SerializeSeq};

use super::{
    AdminError,
    output::{OutputFormat, print_structured},
};

pub trait GoYaml {
    fn serialize_go_yaml<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>;
}

pub struct GoYamlValue<'a, T: ?Sized>(pub &'a T);

impl<T: GoYaml + ?Sized> Serialize for GoYamlValue<'_, T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize_go_yaml(serializer)
    }
}

macro_rules! scalar {
    ($($ty:ty),*) => {$(
        impl GoYaml for $ty {
            fn serialize_go_yaml<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.serialize(serializer)
            }
        }
    )*};
}
scalar!(String, str, u64, i64, i32, bool);

impl<T: GoYaml> GoYaml for Option<T> {
    fn serialize_go_yaml<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Some(value) => serializer.serialize_some(&GoYamlValue(value)),
            None => serializer.serialize_none(),
        }
    }
}

impl<T: GoYaml> GoYaml for Vec<T> {
    fn serialize_go_yaml<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_slice().serialize_go_yaml(serializer)
    }
}

impl<T: GoYaml> GoYaml for [T] {
    fn serialize_go_yaml<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.len()))?;
        for value in self {
            seq.serialize_element(&GoYamlValue(value))?;
        }
        seq.end()
    }
}

macro_rules! impl_go_yaml {
    ($ty:ty { $($field:ident => $name:literal),* $(,)? }) => {
        impl $crate::admin::proto_output::GoYaml for $ty {
            fn serialize_go_yaml<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                use serde::ser::SerializeStruct;
                let mut fields = serializer.serialize_struct(stringify!($ty), [$($name),*].len())?;
                $(fields.serialize_field($name, &$crate::admin::proto_output::GoYamlValue(&self.$field))?;)*
                fields.end()
            }
        }
    };
}
pub(crate) use impl_go_yaml;

pub fn print_proto<T: Serialize + GoYaml>(fmt: OutputFormat, value: &T) -> Result<(), AdminError> {
    if fmt == OutputFormat::Yaml {
        print_structured(fmt, &GoYamlValue(value))
    } else {
        print_structured(fmt, value)
    }
}

pub fn print_proto_list<T: Serialize + GoYaml>(
    fmt: OutputFormat,
    values: &[T],
) -> Result<(), AdminError> {
    // encoding/json emits null for an absent protobuf repeated field. Go's
    // yaml encoder emits [] for the same field.
    if values.is_empty() && matches!(fmt, OutputFormat::Json | OutputFormat::JsonLine) {
        print_structured(fmt, &Option::<u8>::None)
    } else if fmt == OutputFormat::Yaml {
        print_structured(fmt, &GoYamlValue(values))
    } else {
        print_structured(fmt, &values)
    }
}
