fn version_line() -> String {
    format!("enclos {}", env!("CARGO_PKG_VERSION"))
}

fn main() {
    if let Some("--version" | "-V") = std::env::args().nth(1).as_deref() {
        println!("{}", version_line());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_line_includes_crate_version() {
        assert_eq!(
            version_line(),
            format!("enclos {}", env!("CARGO_PKG_VERSION"))
        );
    }
}
