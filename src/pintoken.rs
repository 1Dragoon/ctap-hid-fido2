pub struct PinToken {
    pub key: Vec<u8>,
}

impl PinToken {
    pub fn new(data: &[u8]) -> Self {
        Self { key: data.to_vec() }
    }
}
