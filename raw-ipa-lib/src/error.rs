#[derive(Debug)]
pub enum Error {
    AlreadyExists,
    Internal,
    InvalidId,
    NotEnoughHelpers,
    NotFound,
    TooManyHelpers,

    Hex(hex::FromHexError),
    Io(std::io::Error),
    #[cfg(feature = "enable-serde")]
    Serde(serde_json::Error),
}

macro_rules! forward_errors {
    {$($(#[$a:meta])* $t:path => $v:ident),* $(,)?} => {
        $(
            $(#[$a])*
            impl From<$t> for Error {
                fn from(e: $t) -> Self {
                    Self::$v(e)
                }
            }
        )*

        impl std::error::Error for Error {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                match self {
                    $( $(#[$a])* Self::$v(e) => Some(e), )*
                    _ => None,
                }
            }
        }
    };
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{:?}", self)
    }
}

forward_errors! {
    hex::FromHexError => Hex,
    std::io::Error => Io,
    #[cfg(feature = "enable-serde")]
    serde_json::Error => Serde,
}

pub type Res<T> = Result<T, Error>;
