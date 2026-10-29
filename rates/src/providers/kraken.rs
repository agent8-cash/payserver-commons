//! Kraken exchange rate provider.
//!
//! Uses the Kraken public API to fetch real-time exchange rates.
//! No API key required for public ticker data.

use async_trait::async_trait;
use chrono::Utc;
use rust_decimal::Decimal;
use serde::Deserialize;
use std::collections::HashMap;

use crate::provider::{ExchangeRate, RateError, RateProvider};

/// Kraken exchange rate provider.
///
/// Uses the Kraken public API to fetch exchange rates.
/// Supported pairs depend on Kraken's available markets.
///
/// # Example
///
/// ```rust,ignore
/// let provider = KrakenRateProvider::new(None);
/// let rate = provider.get_rate("USD", "ETH").await?;
/// println!("1 USD = {} ETH", rate.rate);
/// ```
pub struct KrakenRateProvider {
    client: reqwest::Client,
    api_url: String,
}

impl KrakenRateProvider {
    /// Default Kraken API URL.
    pub const DEFAULT_API_URL: &'static str = "https://api.kraken.com/0/public";

    /// Create a new Kraken rate provider.
    ///
    /// # Arguments
    /// * `api_url` - Optional custom API URL. Uses default if None.
    pub fn new(api_url: Option<String>) -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            api_url: api_url.unwrap_or_else(|| Self::DEFAULT_API_URL.to_string()),
        }
    }

    /// Map currency symbols to Kraken's format.
    ///
    /// Kraken uses some non-standard symbols:
    /// - BTC -> XBT
    fn to_kraken_symbol(symbol: &str) -> String {
        match symbol.to_uppercase().as_str() {
            "BTC" => "XBT".to_string(),
            other => other.to_string(),
        }
    }

    /// A rate of exactly one, for the cases that need no exchange at all.
    fn unity(from: &str, to: &str) -> ExchangeRate {
        ExchangeRate {
            from: from.to_string(),
            to: to.to_string(),
            rate: Decimal::ONE,
            timestamp: Utc::now(),
        }
    }

    /// The last traded price for one Kraken pair.
    ///
    /// Separated from [`get_rate`](RateProvider::get_rate) so the pair can be
    /// asked for twice with different orderings, and so an unknown pair is a
    /// distinguishable error rather than something the caller has to parse out
    /// of a message.
    async fn fetch_price(&self, pair_name: &str) -> Result<Decimal, RateError> {
        let url = format!("{}/Ticker?pair={}", self.api_url, pair_name);
        tracing::debug!(pair = %pair_name, "Fetching rate from Kraken");

        let http = self.client.get(&url).send().await?;

        // A throttled request is a statement about this client, not a
        // malformed body. Left to the JSON decoder it surfaces as an opaque
        // "error decoding response body" that hides the real cause. No retry
        // here: retrying a throttled caller only prolongs the throttling, and
        // the fallback and cache layers above already decide what to do.
        if http.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(RateError::ProviderError(format!(
                "kraken returned 429 for \"{pair_name}\""
            )));
        }

        let response: KrakenTickerResponse = http.json().await?;

        if !response.error.is_empty() {
            let error_msg = response.error.join(", ");
            if error_msg.contains("Unknown asset pair") {
                // The pair, not the question. The caller knows which currencies
                // it asked about and may be about to ask the other way round.
                return Err(RateError::UnsupportedPair {
                    from: pair_name.to_string(),
                    to: String::new(),
                });
            }
            return Err(RateError::ProviderError(error_msg));
        }

        let result = response
            .result
            .ok_or_else(|| RateError::InvalidResponse("Missing result in response".to_string()))?;

        // Kraken answers with its own key for the pair, which is often not the
        // one asked for - `XETHZUSD` for `ETHUSD`. One pair was requested, so
        // the single entry is the answer whatever it is called.
        let ticker = result
            .values()
            .next()
            .ok_or_else(|| RateError::InvalidResponse("No ticker data in response".to_string()))?;

        let price_str = ticker
            .c
            .first()
            .ok_or_else(|| RateError::InvalidResponse("No price in ticker data".to_string()))?;

        let price: Decimal = price_str
            .parse()
            .map_err(|e| RateError::InvalidResponse(format!("Invalid price format: {e}")))?;

        if price.is_zero() {
            return Err(RateError::InvalidResponse(
                "Received zero price from exchange".to_string(),
            ));
        }

        Ok(price)
    }

    /// Build the Kraken pair name for a trading pair.
    ///
    /// Kraken pairs are typically CRYPTO/FIAT (e.g., ETHUSD, XBTUSD).
    fn build_pair_name(from: &str, to: &str) -> String {
        let from_kr = Self::to_kraken_symbol(from);
        let to_kr = Self::to_kraken_symbol(to);
        format!("{}{}", to_kr, from_kr)
    }
}

/// Kraken API response for ticker endpoint.
#[derive(Debug, Deserialize)]
struct KrakenTickerResponse {
    error: Vec<String>,
    result: Option<HashMap<String, KrakenTickerData>>,
}

/// Ticker data from Kraken.
#[derive(Debug, Deserialize)]
struct KrakenTickerData {
    /// Last trade: [price, volume]
    c: Vec<String>,
}

#[async_trait]
impl RateProvider for KrakenRateProvider {
    async fn get_rate(&self, from: &str, to: &str) -> Result<ExchangeRate, RateError> {
        let from_upper = from.to_uppercase();
        let to_upper = to.to_uppercase();

        if from_upper == to_upper {
            return Ok(Self::unity(from, to));
        }

        let from_normalized = Self::to_kraken_symbol(&from_upper);
        let to_normalized = Self::to_kraken_symbol(&to_upper);
        if from_normalized == to_normalized {
            return Ok(Self::unity(from, to));
        }

        // Kraken lists one canonical pair per market, as BASE+QUOTE, and
        // prices the base in the quote: ETHUSD, ETHUSDC, ETHXBT. Which side of
        // *our* question is the quote is not something the symbols tell us, so
        // there are two orderings and only one of them exists.
        //
        // The first attempt is the ordering this provider has always used, so
        // nothing that resolves today resolves differently. The second is the
        // fallback that was missing, and it is not an exotic case: a plan
        // priced in USDC asking for ETH built `USDCETH`, which Kraken does not
        // list, and fell through to a provider that quotes crypto against fiat
        // only and could not answer either. Every ETH payment then vanished
        // from that merchant's settled volume.
        let direct = format!("{from_normalized}{to_normalized}");
        let reversed = Self::build_pair_name(from, to);
        let attempts = if crate::is_fiat_currency(&from_upper) {
            [(reversed, true), (direct, false)]
        } else {
            [(direct, false), (reversed, true)]
        };

        let mut found = None;
        for (pair_name, needs_invert) in &attempts {
            match self.fetch_price(pair_name).await {
                Ok(price) => {
                    found = Some((price, *needs_invert));
                    break;
                }
                // Only an unknown pair is worth trying the other way round. A
                // transport failure or a malformed body says nothing about the
                // ordering, and retrying it would double the load on a
                // provider that is already struggling.
                Err(RateError::UnsupportedPair { .. }) => continue,
                Err(e) => return Err(e),
            }
        }

        let Some((price, needs_invert)) = found else {
            return Err(RateError::UnsupportedPair {
                from: from.to_string(),
                to: to.to_string(),
            });
        };

        // `1 from = rate to`. The ticker prices the base in the quote, so when
        // the pair we found is the reverse of the question, the answer is its
        // reciprocal.
        let rate = if needs_invert {
            Decimal::ONE / price
        } else {
            price
        };

        tracing::debug!(
            from = %from,
            to = %to,
            raw_price = %price,
            final_rate = %rate,
            "Rate fetched successfully"
        );

        Ok(ExchangeRate {
            from: from.to_string(),
            to: to.to_string(),
            rate,
            timestamp: Utc::now(),
        })
    }

    fn name(&self) -> &'static str {
        "kraken"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kraken_symbol_mapping() {
        assert_eq!(KrakenRateProvider::to_kraken_symbol("BTC"), "XBT");
        assert_eq!(KrakenRateProvider::to_kraken_symbol("ETH"), "ETH");
        assert_eq!(KrakenRateProvider::to_kraken_symbol("USD"), "USD");
    }

    #[test]
    fn test_kraken_pair_name() {
        // USD -> ETH should query ETHUSD
        assert_eq!(KrakenRateProvider::build_pair_name("USD", "ETH"), "ETHUSD");
        // USD -> BTC should query XBTUSD
        assert_eq!(KrakenRateProvider::build_pair_name("USD", "BTC"), "XBTUSD");
    }

    #[test]
    fn test_kraken_provider_name() {
        let provider = KrakenRateProvider::new(None);
        assert_eq!(provider.name(), "kraken");
    }

    #[tokio::test]
    async fn test_throttled_response_is_reported_as_such() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
            .expect(1)
            .mount(&server)
            .await;

        let provider = KrakenRateProvider::new(Some(server.uri()));
        let err = provider.get_rate("USD", "BTC").await.unwrap_err();
        match err {
            RateError::ProviderError(msg) => assert!(msg.contains("429"), "{msg}"),
            other => panic!("expected ProviderError, got {other:?}"),
        }
    }
}
