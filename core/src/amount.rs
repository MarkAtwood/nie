/// Parse a ZEC decimal string into zatoshi (1 ZEC = 100_000_000 zatoshi).
///
/// Accepts whole numbers ("1") and decimals ("0.001"). Returns an error if
/// the string has more than 8 decimal places, contains non-numeric characters,
/// or would overflow u64.
pub fn parse_zec_to_zatoshi(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (whole, frac) = if let Some((w, f)) = s.split_once('.') {
        (w, f)
    } else {
        (s, "")
    };
    if frac.len() > 8 {
        return Err("too many decimal places (max 8)".to_string());
    }
    let whole: u64 = whole.parse().map_err(|_| "invalid amount".to_string())?;
    let frac_padded = format!("{:0<8}", frac);
    let frac_val: u64 = frac_padded
        .parse()
        .map_err(|_| "invalid decimal".to_string())?;
    whole
        .checked_mul(100_000_000)
        .and_then(|w| w.checked_add(frac_val))
        .ok_or_else(|| "amount overflow".to_string())
}

/// Format a zatoshi amount as a ZEC decimal string.
///
/// Trailing zeros after the decimal point are stripped: 10_000_000 → "0.1".
/// Whole-number amounts have no decimal point: 100_000_000 → "1".
pub fn zatoshi_to_zec_string(zatoshi: u64) -> String {
    let whole = zatoshi / 100_000_000;
    let frac = zatoshi % 100_000_000;
    if frac == 0 {
        whole.to_string()
    } else {
        let s = format!("{whole}.{frac:08}");
        s.trim_end_matches('0').to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Oracle: 1 ZEC = 100_000_000 zatoshi (protocol spec, not derived from code).

    #[test]
    fn parse_whole_number() {
        assert_eq!(parse_zec_to_zatoshi("1"), Ok(100_000_000));
    }

    #[test]
    fn parse_whole_with_dot_zero() {
        assert_eq!(parse_zec_to_zatoshi("1.0"), Ok(100_000_000));
    }

    #[test]
    fn parse_milliunit() {
        assert_eq!(parse_zec_to_zatoshi("0.001"), Ok(100_000));
    }

    #[test]
    fn parse_one_zatoshi() {
        assert_eq!(parse_zec_to_zatoshi("0.00000001"), Ok(1));
    }

    #[test]
    fn parse_nine_decimals_rejected() {
        assert!(parse_zec_to_zatoshi("0.000000001").is_err());
    }

    #[test]
    fn parse_empty_rejected() {
        assert!(parse_zec_to_zatoshi("").is_err());
    }

    #[test]
    fn parse_negative_rejected() {
        assert!(parse_zec_to_zatoshi("-1").is_err());
    }

    #[test]
    fn parse_non_numeric_rejected() {
        assert!(parse_zec_to_zatoshi("abc").is_err());
    }

    #[test]
    fn parse_zero_decimal() {
        assert_eq!(parse_zec_to_zatoshi("0.0"), Ok(0));
    }

    #[test]
    fn parse_max_8_decimals() {
        assert_eq!(parse_zec_to_zatoshi("0.99999999"), Ok(99_999_999));
    }

    #[test]
    fn format_whole() {
        assert_eq!(zatoshi_to_zec_string(100_000_000), "1");
    }

    #[test]
    fn format_milliunit() {
        assert_eq!(zatoshi_to_zec_string(100_000), "0.001");
    }

    #[test]
    fn format_one_zatoshi() {
        assert_eq!(zatoshi_to_zec_string(1), "0.00000001");
    }

    #[test]
    fn format_zero() {
        assert_eq!(zatoshi_to_zec_string(0), "0");
    }

    #[test]
    fn format_tenth() {
        assert_eq!(zatoshi_to_zec_string(10_000_000), "0.1");
    }
}
