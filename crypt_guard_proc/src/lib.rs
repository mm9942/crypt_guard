//! Proc-macros for `crypt_guard`.
//!
//! # Responsibility scope
//! This crate owns five proc-macros:
//! - `activate_log` — attribute macro: injects `initialize_logger(path)` alongside
//!   the annotated `fn`. Now emits a direct call rather than touching any global mutex.
//! - `concat_cipher` — function-like: hex-encodes a `(Vec<u8>, Vec<u8>)` tuple into
//!   a `"key$cipher"` string.
//! - `split_cipher` — function-like: decodes `"key$cipher"` back to `(Vec<u8>, Vec<u8>)`.
//! - `log_activity` — function-like: emits a structured `tracing::info!` event.
//!   The `Lazy<Mutex<Log>>` path has been removed; no mutex is acquired.
//! - `write_log` — function-like: previously flushed a string buffer; now a no-op
//!   (tracing subscribers handle flushing via their own mechanisms).
//!
//! # Backward compatibility
//! All call-site ergonomics are preserved: `log_activity!(process, detail)` and
//! `write_log!()` still compile. Only the generated expansion changes.
//!
//! # Error observability
//! `#[derive(ErrorObservable)]` — constructor-as-observable derive macro. Generates:
//! - Observable constructor methods for every variant annotated with `#[observable(...)]`
//! - Each constructor emits a structured `tracing` event at construction time
//!
//! See the `#[derive(ErrorObservable)]` documentation for usage.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::ParseStream, parse_macro_input, punctuated::Punctuated, Attribute, Data, DeriveInput,
    Expr, Fields, ItemFn, LitStr, MetaNameValue, Token,
};

// ── activate_log ──────────────────────────────────────────────────────────────

/// Attribute macro: injects an `initialize_logger(path)` helper alongside the annotated fn.
///
/// # Usage
/// ```ignore
/// #[activate_log("./app.log")]
/// fn main() { ... }
/// ```
/// The macro appends an `initialize_logger()` function definition after the annotated fn.
/// The caller is responsible for calling `initialize_logger()` at an appropriate point.
#[proc_macro_attribute]
pub fn activate_log(args: TokenStream, input: TokenStream) -> TokenStream {
    let log_file = parse_macro_input!(args as LitStr);
    let input_fn = parse_macro_input!(input as ItemFn);

    let output = quote! {
        #input_fn

        fn initialize_logger() {
            crypt_guard::log::initialize_logger(std::path::PathBuf::from(#log_file));
        }
    };

    TokenStream::from(output)
}

// ── concat_cipher ─────────────────────────────────────────────────────────────

/// Hex-encode a `(key_bytes, cipher_bytes)` tuple into `"hex_key$hex_cipher"`.
///
/// # Usage
/// ```ignore
/// let combined: String = concat_cipher!((key_vec, cipher_vec));
/// ```
#[proc_macro]
pub fn concat_cipher(input: TokenStream) -> TokenStream {
    let inputs = parse_macro_input!(input as Expr);

    let output = quote! {
        {
            let key = hex::encode(#inputs.0);
            let cipher = hex::encode(#inputs.1);
            format!("{}${}", key, cipher)
        }
    };

    TokenStream::from(output)
}

// ── split_cipher ──────────────────────────────────────────────────────────────

/// Decode a `"hex_key$hex_cipher"` string back to `(Vec<u8>, Vec<u8>)`.
///
/// # Usage
/// ```ignore
/// let (key, cipher): (Vec<u8>, Vec<u8>) = split_cipher!(combined_str)?;
/// ```
#[proc_macro]
pub fn split_cipher(input: TokenStream) -> TokenStream {
    let expr = parse_macro_input!(input as Expr);

    let output = quote! {
        {
            let parts: Vec<&str> = #expr.split('$').collect();
            if parts.len() != 2 {
                Err(hex::FromHexError::OddLength)
            } else {
                match (hex::decode(parts[0]), hex::decode(parts[1])) {
                    (Ok(key), Ok(cipher)) => Ok((key, cipher)),
                    (Err(e), _) | (_, Err(e)) => Err(e),
                }
            }
        }
    };

    TokenStream::from(output)
}

// ── log_activity ──────────────────────────────────────────────────────────────

struct LogActivityInput {
    process: Expr,
    detail: Expr,
}

impl syn::parse::Parse for LogActivityInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let process: Expr = input.parse()?;
        input.parse::<Token![,]>()?;
        let detail: Expr = input.parse()?;
        Ok(LogActivityInput { process, detail })
    }
}

/// Emit a structured `tracing::info!` event for a named activity.
///
/// # Description
/// Previously locked the global `LOGGER` mutex and called `append_log`. This expansion
/// now emits a direct `tracing::info!` event. No mutex is acquired; no string buffer
/// is modified. Compatible with async runtimes.
///
/// # Usage
/// ```ignore
/// log_activity!("encrypt_file", format!(" path={}", path.display()));
/// ```
#[proc_macro]
pub fn log_activity(input: TokenStream) -> TokenStream {
    let LogActivityInput { process, detail } = parse_macro_input!(input as LogActivityInput);

    let output = quote! {
        tracing::info!(
            phase = %format!("{}", #process),
            detail = %format!("{}", #detail),
            "crypt_guard activity"
        )
    };

    TokenStream::from(output)
}

// ── write_log ─────────────────────────────────────────────────────────────────

/// No-op flush macro — previously wrote the string buffer to a log file.
///
/// # Description
/// The `Lazy<Mutex<Log>>` global and its string buffer have been removed. Tracing
/// subscribers handle their own flushing (e.g. tracing-appender flushes on Drop).
/// This macro is retained as a no-op so that existing call sites compile unchanged.
///
/// # Usage
/// ```ignore
/// write_log!();   // no-op; safe to call anywhere
/// ```
#[proc_macro]
pub fn write_log(_input: TokenStream) -> TokenStream {
    // No-op: tracing subscribers flush themselves.
    let output = quote! { () };
    TokenStream::from(output)
}

// ── ErrorObservable derive ────────────────────────────────────────────────────

/// Derive macro: generate observable constructors for error enum variants.
///
/// # Description
/// For each variant annotated with `#[observable(level = "...", event = "...")]`, generates:
/// - A `snake_case` constructor method on `Self` that:
///   1. Emits a structured `tracing` event at the specified level.
///   2. Constructs and returns the variant.
/// - Handles unit variants, tuple variants (single field `source`), and struct variants.
///
/// # Attributes
/// `#[observable(level = "error|warn|info|debug|trace", event = "domain.event_name")]`
///
/// - `level`: tracing level at which the event fires when the variant is constructed.
/// - `event`: structured event name (appears as the `event` field in the tracing event).
///
/// # Usage
/// ```ignore
/// #[derive(ErrorObservable)]
/// pub enum MyError {
///     #[observable(level = "error", event = "auth.forbidden")]
///     Forbidden { user_id: String },
///
///     #[observable(level = "warn", event = "auth.not_found")]
///     NotFound(String),
///
///     Plain,  // variants without #[observable] get no constructor
/// }
/// ```
/// Generates (approximately):
/// ```ignore
/// impl MyError {
///     pub fn forbidden(user_id: String) -> Self {
///         tracing::error!(event = "auth.forbidden", %user_id, "MyError");
///         MyError::Forbidden { user_id }
///     }
///     pub fn not_found(arg0: String) -> Self {
///         tracing::warn!(event = "auth.not_found", ?arg0, "MyError");
///         MyError::NotFound(arg0)
///     }
/// }
/// ```
#[proc_macro_derive(ErrorObservable, attributes(observable))]
pub fn derive_error_observable(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);

    let enum_name = &ast.ident;

    let variants = match &ast.data {
        Data::Enum(data) => &data.variants,
        _ => {
            return syn::Error::new_spanned(
                &ast.ident,
                "ErrorObservable can only be derived for enums",
            )
            .to_compile_error()
            .into();
        }
    };

    let mut constructors = Vec::new();

    for variant in variants {
        // Only generate a constructor if the variant has an #[observable(...)] attribute.
        let observable_attr = variant
            .attrs
            .iter()
            .find(|a| a.path().is_ident("observable"));

        let obs = match observable_attr {
            Some(a) => a,
            None => continue,
        };

        // Parse level = "...", event = "..." from the attribute.
        let (level_str, event_str) = match parse_observable_attr(obs) {
            Ok(v) => v,
            Err(e) => return e.to_compile_error().into(),
        };

        let variant_name = &variant.ident;
        // Generate constructor name as snake_case of variant name.
        let constructor_name = {
            let s = variant_name.to_string();
            let snake = to_snake_case(&s);
            syn::Ident::new(&snake, variant_name.span())
        };

        let event_lit = syn::LitStr::new(&event_str, proc_macro2::Span::call_site());
        let enum_name_str = enum_name.to_string();
        let enum_name_lit = syn::LitStr::new(&enum_name_str, enum_name.span());

        // Build the tracing macro call and constructor body based on variant fields.
        let constructor = match &variant.fields {
            Fields::Unit => {
                let trace_call = make_trace_call(&level_str, &event_lit, &enum_name_lit, &[]);
                quote! {
                    /// Observable constructor — emits a tracing event at construction time.
                    pub fn #constructor_name() -> Self {
                        #trace_call;
                        #enum_name::#variant_name
                    }
                }
            }
            Fields::Unnamed(fields) => {
                let args: Vec<_> = (0..fields.unnamed.len())
                    .map(|i| {
                        let name =
                            syn::Ident::new(&format!("arg{}", i), proc_macro2::Span::call_site());
                        let ty = &fields.unnamed[i].ty;
                        (name, ty)
                    })
                    .collect();
                let arg_names: Vec<_> = args.iter().map(|(n, _)| n).collect();
                let arg_decls: Vec<_> = args.iter().map(|(n, t)| quote! { #n: #t }).collect();
                let field_tokens: Vec<_> = arg_names.iter().map(|n| quote! { ?#n }).collect();
                let trace_call =
                    make_trace_call(&level_str, &event_lit, &enum_name_lit, &field_tokens);
                quote! {
                    /// Observable constructor — emits a tracing event at construction time.
                    pub fn #constructor_name(#(#arg_decls),*) -> Self {
                        #trace_call;
                        #enum_name::#variant_name(#(#arg_names),*)
                    }
                }
            }
            Fields::Named(fields) => {
                let args: Vec<_> = fields
                    .named
                    .iter()
                    .map(|f| {
                        let name = f.ident.as_ref().unwrap();
                        let ty = &f.ty;
                        (name, ty)
                    })
                    .collect();
                let arg_names: Vec<_> = args.iter().map(|(n, _)| *n).collect();
                let arg_decls: Vec<_> = args.iter().map(|(n, t)| quote! { #n: #t }).collect();
                let field_tokens: Vec<_> = arg_names.iter().map(|n| quote! { %#n }).collect();
                let trace_call =
                    make_trace_call(&level_str, &event_lit, &enum_name_lit, &field_tokens);
                quote! {
                    /// Observable constructor — emits a tracing event at construction time.
                    pub fn #constructor_name(#(#arg_decls),*) -> Self {
                        #trace_call;
                        #enum_name::#variant_name { #(#arg_names),* }
                    }
                }
            }
        };

        constructors.push(constructor);
    }

    if constructors.is_empty() {
        return TokenStream::from(quote! {});
    }

    let output = quote! {
        impl #enum_name {
            #(#constructors)*
        }
    };

    TokenStream::from(output)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse `level = "...", event = "..."` from an `#[observable(...)]` attribute.
fn parse_observable_attr(attr: &Attribute) -> syn::Result<(String, String)> {
    let mut level = String::new();
    let mut event = String::new();

    attr.parse_args_with(|input: ParseStream| {
        let pairs = Punctuated::<MetaNameValue, Token![,]>::parse_terminated(input)?;
        for pair in &pairs {
            let key = pair
                .path
                .get_ident()
                .map(|i| i.to_string())
                .unwrap_or_default();
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(s),
                ..
            }) = &pair.value
            {
                match key.as_str() {
                    "level" => level = s.value(),
                    "event" => event = s.value(),
                    _ => {}
                }
            }
        }
        Ok(())
    })?;

    if level.is_empty() || event.is_empty() {
        return Err(syn::Error::new_spanned(
            attr,
            "observable attribute requires level = \"...\" and event = \"...\"",
        ));
    }
    Ok((level, event))
}

/// Build the tracing macro call token stream.
fn make_trace_call(
    level: &str,
    event_lit: &syn::LitStr,
    enum_name_lit: &syn::LitStr,
    fields: &[proc_macro2::TokenStream],
) -> proc_macro2::TokenStream {
    let fields_ts = if fields.is_empty() {
        quote! {}
    } else {
        quote! { #(#fields,)* }
    };

    match level {
        "error" => quote! { tracing::error!(#fields_ts event = #event_lit, #enum_name_lit) },
        "warn" => quote! { tracing::warn!(#fields_ts event = #event_lit, #enum_name_lit) },
        "info" => quote! { tracing::info!(#fields_ts event = #event_lit, #enum_name_lit) },
        "debug" => quote! { tracing::debug!(#fields_ts event = #event_lit, #enum_name_lit) },
        _ => quote! { tracing::trace!(#fields_ts event = #event_lit, #enum_name_lit) },
    }
}

/// Convert `PascalCase` to `snake_case`.
fn to_snake_case(s: &str) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_lowercase().next().unwrap_or(c));
    }
    out
}
