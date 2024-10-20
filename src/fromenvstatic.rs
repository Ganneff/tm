////////////////////////////////////////////////////////////////////////
// Macros
////////////////////////////////////////////////////////////////////////
/// Help setting up static variables based on user environment.
///
/// We allow the user to configure certain properties/behaviours of tm
/// using environment variables. To reduce boilerplate in code, we use a
/// macro for setting them. We use [mod@`lazy_static`] to define them as
/// global variables, so they are available throughout the whole program -
/// they aren't going to change during runtime, ever, anyways.
///
/// # Examples
///
/// ```
/// # fn main() {
/// static ref TMPDIR: String = fromenvstatic!(asString "TMPDIR", "/tmp");
/// static ref TMSORT: bool = fromenvstatic!(asBool "TMSORT", true);
/// static ref TMWIN: u8 = fromenvstatic!(asU32 "TMWIN", 1);
/// # }
/// ```
macro_rules! fromenvstatic {
    (asString $envvar:literal, $default:expr) => {
            match env::var($envvar) {
                Ok(val) => val,
                Err(_) => $default.to_string(),
            }
    };
    (asBool $envvar:literal, $default:literal) => {
        match env::var($envvar) {
            Ok(val) => match val.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                &_ => {
                    // Test run as "cargo test -- --nocapture" will print this
                    if cfg!(test) {
                        println!(
                            "Variable {} expects true or false, not {}, assuming {}",
                            $envvar, val, $default
                        );
                    }
                    error!(
                        "Variable {} expects true or false, not {}, assuming {}",
                        $envvar, val, $default
                    );
                    return $default;
                }
            },
            Err(_) => $default,
        }
    };
    (asU32 $envvar:literal, $default:literal) => {
        match env::var($envvar) {
            Ok(val) => {
                return val.parse::<u32>().unwrap_or_else(|err| {
                    if cfg!(test) {
                        println!(
                            "Couldn't parse variable {} (value: {}) as number (error: {}), assuming {}",
                            $envvar, val, err, $default
                        );
                    }
                    error!(
                        "Couldn't parse variable {} (value: {}) as number (error: {}), assuming {}",
                        $envvar, val, err, $default
                    );
                    $default
                });
            }
            Err(_) => $default,
        }
    };
}
