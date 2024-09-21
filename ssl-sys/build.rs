use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=src/wrapped_ssl.h");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=ssl");

    let bindings = bindgen::Builder::default()
        // .clang_args(&[
        //     "-L/opt/homebrew/Cellar/openssl@3/3.3.2/lib",
        //     "-I/opt/homebrew/Cellar/openssl@3/3.3.2/include",
        //     "-Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.3.2/lib"
        // ])
        .header("src/wrapped_ssl.h")
        // ALLOW FUNCTION NAMES
        .allowlist_function("ASN1_.*")
        .allowlist_function("BIO_.*")
        .allowlist_function("EVP_.*")
        .allowlist_function("ERR_.*")
        .allowlist_function("OSSL_P.*")
        .allowlist_function("OCSP_.*")
        .allowlist_function("X509_.*")
        .allowlist_function("X509V3_.*")
        .allowlist_function("TS_.*")
        .allowlist_function("BN_.*")
        .allowlist_function("d2i_.*")
        .allowlist_function("PEM_.*")
        .allowlist_function("OBJ_.*")
        .allowlist_function("GENERAL_.*")
        // ALLOW TYPE NAMES
        .allowlist_type("ASN1_.*")
        .allowlist_type("BIO_.*")
        .allowlist_type("EVP_.*")
        .allowlist_type("OBJ_.*")
        .allowlist_type("OSSL_P.*")
        .allowlist_type("OCSP_.*")
        .allowlist_type("X509_.*")
        .allowlist_type("TS_.*")
        .allowlist_type("BN_.*")
        .allowlist_type("GENERAL_.*")
        // ALLOW VARS NAMES
        .allowlist_var("BIO_CTRL_.*")
        .allowlist_var("EVP_.*")
        .allowlist_var("OSSL_P.*")
        .allowlist_var("SN_.*")
        .allowlist_var("LN_.*")
        .allowlist_var("NID_.*")
        .allowlist_var("MBSTRING_ASC")
        .allowlist_var("XN_.*")
        .allowlist_var("KU_.*")
        .allowlist_var("XKU_.*")
        .allowlist_var("GEN_.*")
        .allowlist_var("V_ASN1_.*")
        .generate_cstr(true)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
