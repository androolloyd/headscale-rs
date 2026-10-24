mod socket;
pub mod tls;

pub use socket::{
    connect_tcp, connect_tcp_addr, connect_uds, resolve_tcp, BufferedSocket, Socket, SocketIntoBox,
    WithSocket, WriteBuffer,
};
