//! Recovery phrase setup component.

use leptos::prelude::*;

use crate::components::copy::CopyButton;

/// Recovery setup step.
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryStep {
    /// Show recovery phrase.
    ShowPhrase,
    /// Confirm user has saved phrase.
    Confirm,
    /// Setup complete.
    Complete,
}

/// Recovery setup component.
///
/// Shows the recovery mnemonic phrase and allows the user to confirm
/// they've saved it, or skip for now.
#[component]
pub fn RecoverySetup(
    /// The mnemonic phrase words.
    mnemonic_words: Vec<String>,
    /// Callback when user confirms they've saved the phrase.
    on_confirm: Callback<()>,
    /// Callback when user skips recovery setup.
    on_skip: Callback<()>,
    /// The account id, shown alongside the phrase when the account has no other
    /// handle.
    ///
    /// A passkey-only account has no email and no wallet address, so the account
    /// id is the ONLY thing it can be identified by at recovery. The
    /// phrase alone is not enough - recovery needs an identifier too, and a
    /// merchant who saved only the words would have nothing to type.
    /// Presented as one unit with the phrase so both get saved together.
    // `optional_no_strip` keeps the Option in the builder: plain `optional`
    // auto-wraps, so the caller would have to pass a bare String and could not
    // express "passkey-only accounts only".
    #[prop(optional_no_strip)]
    account_id: Option<String>,
    /// Whether to offer a "Skip for Now" button (default: `false`).
    ///
    /// Safe by default: this component is exported, so a consumer that says
    /// nothing should get the flow that cannot strand an account. See
    /// `RegisterPage::require_recovery`.
    #[prop(optional, default = false)]
    allow_skip: bool,
    /// Whether a request is in progress (disables buttons).
    #[prop(optional)]
    loading: Signal<bool>,
) -> impl IntoView {
    let (step, set_step) = signal(RecoveryStep::ShowPhrase);
    let (confirmed, set_confirmed) = signal(false);
    let is_loading = move || loading.get();

    let words = mnemonic_words.clone();
    let word_count = words.len();
    // Built here rather than inside the view: `words` is moved into the closure
    // below, and the label states the real count rather than a hardcoded 24 -
    // this component is also used for 12-word phrases.
    let phrase_for_copy = mnemonic_words.join(" ");

    let handle_continue = move |_| {
        set_step.set(RecoveryStep::Confirm);
    };

    let handle_confirm = move |_| {
        if confirmed.get() && !is_loading() {
            // Don't set step to Complete here - let parent handle success
            on_confirm.run(());
        }
    };

    let handle_skip = {
        move |_| {
            on_skip.run(());
        }
    };

    view! {
        <div class="ps-recovery-setup">
            {move || match step.get() {
                RecoveryStep::ShowPhrase => {
                    let words = words.clone();
                    // Cloned per render for the same reason `words` is: this is
                    // an FnMut reactive closure, so moving the String out of the
                    // capture does not compile.
                    let phrase_for_copy = phrase_for_copy.clone();
                    view! {
                        <div class="ps-recovery-show">
                            <h3 class="ps-recovery-title">"Save Your Recovery Phrase"</h3>
                            <p class="ps-recovery-description">
                                // Honest about the current state: the phrase is real and
                                // bound to the account, but no recovery flow exists yet,
                                // so promising it "recovers your account" is a
                                // promise the product cannot keep today.
                                "Write down these " {word_count} " words in order and keep them safe. "
                                "Account recovery is not available yet — when it ships, this "
                                "phrase is what will restore access, and it cannot be reissued."
                            </p>

                            <div class="ps-mnemonic-grid">
                                {words.iter().enumerate().map(|(i, word)| {
                                    let word = word.clone();
                                    view! {
                                        <div class="ps-mnemonic-word">
                                            <span class="ps-mnemonic-index">{i + 1}</span>
                                            <span class="ps-mnemonic-text">{word}</span>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>

                            // Space-separated, NOT the numbered form on screen:
                            // that is what every wallet's restore field accepts,
                            // and a merchant pasting "1 abandon 2 ability" into
                            // one would be told the phrase is invalid with no
                            // hint as to why.
                            //
                            // `CopyButton` and not a local handler: it awaits the
                            // clipboard write before reporting success. The
                            // checkout page learned that the hard way, and a copy
                            // button that lies about a recovery phrase is worse
                            // than no button - the merchant closes the page
                            // believing they have it.
                            <div class="ps-mnemonic-copy">
                                <CopyButton
                                    text=phrase_for_copy
                                    label=format!("Copy all {word_count} words")
                                    class="ps-btn-sm"
                                />
                            </div>

                            {account_id.clone().map(|id| view! {
                                <div class="ps-recovery-account-id">
                                    <span class="ps-recovery-account-id-label">
                                        "Account ID — save this with your phrase"
                                    </span>
                                    <code class="ps-recovery-account-id-value">{id}</code>
                                    <span class="ps-recovery-account-id-hint">
                                        "Recovery needs both: this identifies the account, "
                                        "the phrase proves it is yours."
                                    </span>
                                </div>
                            })}

                            <div class="ps-recovery-warning">
                                <WarningIcon />
                                <p>
                                    "Never share your recovery phrase. Once recovery ships, "
                                    "anyone with these words will be able to take over your account."
                                </p>
                            </div>

                            <div class="ps-recovery-actions">
                                <button
                                    type="button"
                                    class="ps-button ps-button-primary"
                                    disabled=is_loading
                                    on:click=handle_continue
                                >
                                    "I've Written It Down"
                                </button>
                                {if allow_skip {
                                    view! {
                                        <button
                                            type="button"
                                            class="ps-button ps-button-ghost"
                                            disabled=is_loading
                                            on:click=handle_skip
                                        >
                                            {move || if is_loading() { "Processing..." } else { "Skip for Now" }}
                                        </button>
                                    }.into_any()
                                } else {
                                    let _: () = view! { <></> };
                                    ().into_any()
                                }}
                            </div>
                        </div>
                    }.into_any()
                }

                RecoveryStep::Confirm => view! {
                    <div class="ps-recovery-confirm">
                        <h3 class="ps-recovery-title">"Confirm Your Recovery Phrase"</h3>
                        <p class="ps-recovery-description">
                            "Please confirm that you have saved your recovery phrase securely."
                        </p>

                        <label class="ps-checkbox-label">
                            <input
                                type="checkbox"
                                class="ps-checkbox"
                                prop:checked=move || confirmed.get()
                                on:change=move |ev| {
                                    set_confirmed.set(event_target_checked(&ev));
                                }
                            />
                            <span>
                                // Honest about the current state, same as the ShowPhrase step
                                // above: no recovery redemption flow exists yet, and invoice
                                // metadata is not yet encrypted client-side either. So this
                                // covers funds loss, holding no copy, and no back door, but
                                // leaves out a data-loss clause that would not be true yet and
                                // keeps saying recovery isn't live today.
                                "I have written down my recovery phrase and stored it securely. "
                                "I understand that random.cash is non-custodial: random.cash holds "
                                "no copy of my recovery phrase, my account key, or my funds, and "
                                "support cannot override this — there is no back door, deliberately. "
                                "If I lose access to my account, I lose access to my funds "
                                "permanently. Account recovery is not available in this release, so "
                                "right now this phrase is not yet a way back in if I lose my "
                                "sign-in method."
                            </span>
                        </label>

                        <div class="ps-recovery-actions">
                            <button
                                type="button"
                                class="ps-button ps-button-primary"
                                // The only gate before `handle_confirm` fires the same
                                // account-creation request that persists the account, so a
                                // completed registration is itself evidence the merchant
                                // passed through this checkbox. `RegisterPage` defaults
                                // `require_recovery` to `true`, and its one caller never
                                // overrides it, so no real registration has a path around
                                // this button.
                                disabled=move || !confirmed.get() || is_loading()
                                on:click=handle_confirm
                            >
                                {move || if is_loading() { "Completing..." } else { "Complete Setup" }}
                            </button>
                            <button
                                type="button"
                                class="ps-button ps-button-ghost"
                                disabled=is_loading
                                on:click=move |_| set_step.set(RecoveryStep::ShowPhrase)
                            >
                                "Back"
                            </button>
                        </div>
                    </div>
                }.into_any(),

                RecoveryStep::Complete => view! {
                    <div class="ps-recovery-complete">
                        <SuccessIcon />
                        <h3 class="ps-recovery-title">"Recovery Phrase Saved"</h3>
                        <p class="ps-recovery-description">
                            "Keep it somewhere safe. Recovery is not available in this "
                            "release, so it is not yet a way back into your account."
                        </p>
                    </div>
                }.into_any(),
            }}
        </div>
    }
}

/// Warning icon component.
#[component]
fn WarningIcon() -> impl IntoView {
    view! {
        <svg
            class="ps-warning-icon"
            width="20"
            height="20"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
            <path d="M12 9v4" />
            <path d="M12 17h.01" />
        </svg>
    }
}

/// Success/checkmark icon component.
#[component]
fn SuccessIcon() -> impl IntoView {
    view! {
        <svg
            class="ps-success-icon"
            width="48"
            height="48"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
        >
            <circle cx="12" cy="12" r="10" />
            <path d="m9 12 2 2 4-4" />
        </svg>
    }
}
