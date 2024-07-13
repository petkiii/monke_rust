use std::{error::Error, fmt};

#[derive(Debug)]
pub(crate) struct MonkeError {
    text: String,
}

impl Error for MonkeError {}

impl fmt::Display for MonkeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        return write!(f, "Error: {}", &self.text);
    }
}

impl MonkeError {
    pub(crate) fn new(text: String) -> Self {
        return MonkeError { text };
    }
}

#[macro_export]
macro_rules! monke_error {
    ($($arg:tt)*) => {
        $crate::MonkeError::new(format!($($arg)*))
        .into()
    };
}
