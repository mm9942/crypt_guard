extern crate proc_macro;

use proc_macro::{TokenStream};
use quote::quote;
use syn::{parse_macro_input, ItemFn, Meta, Lit, LitStr, Expr};

#[proc_macro_attribute]
pub fn activate_log(args: TokenStream, input: TokenStream) -> TokenStream {
    let log_file = parse_macro_input!(args as LitStr);
    let input_fn = parse_macro_input!(input as ItemFn);

    let output = quote! {
        #input_fn

        fn initialize_logger() {
            crypt_guard::initialize_logger(std::path::PathBuf::from(#log_file));
        }
    };

    TokenStream::from(output)
}

#[proc_macro]
pub fn ConcatCipher(input: TokenStream) -> TokenStream {
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

#[proc_macro]
pub fn SplitCipher(input: TokenStream) -> TokenStream {
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

struct LogActivityInput {
    process: Expr,
    detail: Expr,
}

impl syn::parse::Parse for LogActivityInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let process: Expr = input.parse()?;
        input.parse::<syn::Token![,]>()?;
        let detail: Expr = input.parse()?;

        Ok(LogActivityInput { process, detail })
    }
}

#[proc_macro]
pub fn log_activity(input: TokenStream) -> TokenStream {
    let LogActivityInput { process, detail } = parse_macro_input!(input as LogActivityInput);

    let output = quote! {
        match LOGGER.lock() {
            Ok(mut logger) => {
                let _ = logger.append_log(&format!("{}", #process), &format!("{}", #detail));
            },
            Err(e) => eprintln!("Logger lock error: {}", e),
        }
    };

    TokenStream::from(output)
}

#[proc_macro]
pub fn write_log(_input: TokenStream) -> TokenStream {
    let output = quote! {
        {
            let mut logger = LOGGER.lock().expect("Logger lock failed");
            if let Err(e) = logger.write_log_file() {
                eprintln!("Failed to write log file: {:?}", e);
            }
            logger.log.clear();
        }
    };

    TokenStream::from(output)
}
