use crate::authenticator::inner::InnerAuthenticator;
use crate::authenticator::pin::PinInner;
use crate::authenticator::Authenticator;
use authenticator::protocol::credential::Credential;
use std::time::{Duration, Instant};

use crate::authenticator::protocol::hpke_format::HPKEMode::{Auth, AuthPsk, Base, Psk};
use colored::*;
use dialoguer::{Input, Select};

pub mod authenticator;
#[cfg(test)]
mod test;
mod bench;

use std::fs;

pub fn export_file(file_path: &str, content: String) -> Result<(), String> {
    fs::write(file_path, content).map_err(|e| e.to_string())
}
pub fn import_from_file(file_path: &str) -> Result<String, String> {
    fs::read_to_string(file_path).map_err(|e| e.to_string())
}

// Display the application banner
fn banner() {
    println!("{}", "-".repeat(30).bold().green());
    println!("{:}", "FIDO凭证交换协议仿真".green().bold());
    println!("{:}", "250114v02".green().bold());
    println!("{}", "-".repeat(30).bold().green());
}

fn list_creds<T: InnerAuthenticator>(a: &Authenticator<T>) {
    match a.inner.get_credentials() {
        Ok(creds) => creds.iter().enumerate().for_each(|(index, cred)| {
            println!("{} : {}", index, cred.get_rp_id());
        }),
        Err(e) => {
            println!("获取凭证列表时发生错误：{}", e)
        }
    };
}

fn request<T: InnerAuthenticator>(a: &Authenticator<T>) {
    let name: String = Input::new()
        .with_prompt("输入导入凭证的RPID:")
        .interact_text()
        .unwrap();
    let export_request = a
        .construct_export_request(name.to_string())
        .expect("Construct Error");
    if let Err(e) = export_file("request.json", export_request) {
        println!("{}", ColoredString::from(e).red().bold());
    } else {
        println!("{}", "请求已导出到request.json中");
    }
}
fn export<T: InnerAuthenticator>(a: &Authenticator<T>) {
    let name: String = Input::new()
        .with_prompt("输入导入请求文件路径")
        .interact_text()
        .unwrap();

    let export = || -> Result<(), String> {
        let export_request = import_from_file(&name.to_string())?;
        let res = a
            .handle_request(export_request)
            .map_err(|e| e.to_string())?;
        export_file("response.json", res)
    };
    if let Err(e) = export() {
        println!("导出错误：{}", ColoredString::from(e).red().bold());
    } else {
        println!("凭证已导出到response.json");
    }
}
fn import<T: InnerAuthenticator>(a: &Authenticator<T>) {
    let name: String = Input::new()
        .with_prompt("输入导出相应文件路径")
        .interact_text()
        .unwrap();

    let export = || -> Result<String, String> {
        let export = import_from_file(&name.to_string())?;
        a.handle_response(export).map_err(|e| e.to_string())
    };
    if let Err(e) = export() {
        println!("导入错误：{}", ColoredString::from(e).red().bold());
    }
}
fn interact() {
    let auth = Authenticator {
        inner: PinInner::default(),
    };

    banner();
    loop {
        let options = [
            "  查看已有凭证",
            "  请求导出凭证",
            "  导出凭证",
            "  导入凭证",
            "  退出",
        ];
        let selection = Select::new()
            .with_prompt("选择")
            .items(&options)
            .interact()
            .unwrap();
        match selection {
            0 => list_creds(&auth),
            1 => request(&auth),
            2 => export(&auth),
            3 => import(&auth),
            4 => {
                println!("{}", "退出程序".green());
                break;
            }
            _ => unreachable!(),
        }
    }
}

fn main() {
    interact();
    // time_test();
}
