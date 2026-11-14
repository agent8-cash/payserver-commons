//! Currency detection and classification utilities.

/// Common fiat currency codes (ISO 4217).
pub const FIAT_CURRENCIES: &[&str] = &[
    // Major currencies
    "USD", // US Dollar
    "EUR", // Euro
    "GBP", // British Pound
    "JPY", // Japanese Yen
    "CHF", // Swiss Franc
    "CNY", // Chinese Yuan
    // Americas
    "CAD", // Canadian Dollar
    "MXN", // Mexican Peso
    "BRL", // Brazilian Real
    "ARS", // Argentine Peso
    "CLP", // Chilean Peso
    "COP", // Colombian Peso
    "PEN", // Peruvian Sol
    // Asia-Pacific
    "AUD", // Australian Dollar
    "NZD", // New Zealand Dollar
    "SGD", // Singapore Dollar
    "HKD", // Hong Kong Dollar
    "KRW", // South Korean Won
    "INR", // Indian Rupee
    "IDR", // Indonesian Rupiah
    "THB", // Thai Baht
    "VND", // Vietnamese Dong
    "PHP", // Philippine Peso
    "MYR", // Malaysian Ringgit
    "TWD", // Taiwan Dollar
    // Europe
    "SEK", // Swedish Krona
    "NOK", // Norwegian Krone
    "DKK", // Danish Krone
    "PLN", // Polish Zloty
    "CZK", // Czech Koruna
    "HUF", // Hungarian Forint
    "RON", // Romanian Leu
    "BGN", // Bulgarian Lev
    "HRK", // Croatian Kuna
    "RUB", // Russian Ruble
    "UAH", // Ukrainian Hryvnia
    "TRY", // Turkish Lira
    // Middle East & Africa
    "ILS", // Israeli Shekel
    "AED", // UAE Dirham
    "SAR", // Saudi Riyal
    "ZAR", // South African Rand
    "EGP", // Egyptian Pound
    "NGN", // Nigerian Naira
    "KES", // Kenyan Shilling
];

/// Check if a currency code is a fiat currency.
///
/// This function performs a case-insensitive comparison against
/// the list of known fiat currency codes.
///
/// # Examples
///
/// ```
/// use rates::is_fiat_currency;
///
/// assert!(is_fiat_currency("USD"));
/// assert!(is_fiat_currency("usd")); // case-insensitive
/// assert!(is_fiat_currency("EUR"));
/// assert!(!is_fiat_currency("ETH"));
/// assert!(!is_fiat_currency("BTC"));
/// ```
pub fn is_fiat_currency(currency: &str) -> bool {
    let upper = currency.to_uppercase();
    FIAT_CURRENCIES.contains(&upper.as_str())
}

/// Check if a currency code is a cryptocurrency (not fiat).
///
/// This is simply the inverse of `is_fiat_currency`.
/// Note: This doesn't validate that the currency code is a valid crypto,
/// it just checks that it's not a known fiat currency.
///
/// # Examples
///
/// ```
/// use rates::is_fiat_currency;
///
/// // Cryptos are not fiat
/// assert!(!is_fiat_currency("ETH"));
/// assert!(!is_fiat_currency("BTC"));
/// assert!(!is_fiat_currency("USDC"));
/// ```
pub fn is_crypto_currency(currency: &str) -> bool {
    !is_fiat_currency(currency)
}
/// Convert an amount in major units to minor units (e.g., dollars to cents).
/// Handles zero‑decimal currencies (e.g., JPY) by returning the amount unchanged.
///
/// # Arguments
/// * `amount` – Amount in major units as a `u64`.
/// * `currency` – ISO 4217 currency code.
///
/// # Returns
/// Minor‑unit representation as `u64`.
pub fn convert_to_minor_units(amount: u64, currency: &str) -> u64 {
    // List of zero‑decimal currency codes per ISO 4217.
    const ZERO_DECIMAL: &[&str] = &[
        "BIF", "CLP", "DJF", "GNF", "JPY", "KMF", "KRW", "MGA",
        "PYG", "RWF", "UGX", "VND", "VUV", "XAF", "XOF", "XPF",
    ];
    let upper = currency.to_uppercase();
    if ZERO_DECIMAL.contains(&upper.as_str()) {
        amount
    } else {
        // Default: two decimal places (cents). Adjust if needed.
        amount * 100
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fiat_currencies() {
        // Major fiats
        assert!(is_fiat_currency("USD"));
        assert!(is_fiat_currency("EUR"));
        assert!(is_fiat_currency("GBP"));
        assert!(is_fiat_currency("JPY"));

        // Case insensitive
        assert!(is_fiat_currency("usd"));
        assert!(is_fiat_currency("Eur"));
        assert!(is_fiat_currency("gbP"));
    }

    #[test]
    fn test_crypto_currencies() {
        // Common cryptos should not be fiat
        assert!(!is_fiat_currency("ETH"));
        assert!(!is_fiat_currency("BTC"));
        assert!(!is_fiat_currency("USDC"));
        assert!(!is_fiat_currency("USDT"));
        assert!(!is_fiat_currency("DAI"));
        assert!(!is_fiat_currency("MATIC"));
        assert!(!is_fiat_currency("POL"));
    }

    #[test]
    fn test_convert_to_minor_units() {
        // Non-zero-decimal currency (USD) should multiply by 100
        assert_eq!(convert_to_minor_units(12, "USD"), 1200);
        // Zero‑decimal currency (JPY) should remain unchanged
        assert_eq!(convert_to_minor_units(1234, "JPY"), 1234);
    }

    #[test]
    fn test_is_crypto_currency() {
        assert!(is_crypto_currency("ETH"));
        assert!(is_crypto_currency("BTC"));

}
