use crate::authenticator::inner::InnerAuthenticator;
use crate::authenticator::pin::PinInner;
use crate::authenticator::Authenticator;
use authenticator::protocol::{
    credential::Credential,
    file::{export_file, import_from_file},
};

use colored::*;
use dialoguer::{Input, Select};
#[allow(unused)]

pub mod authenticator;
pub mod crypto;
mod test;
//BFAB-9FAO-6JDA-GSDX-YXKF-C7SJ-B5OT

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
        .construct_export_request_base(name.to_string())
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

    let export = || -> Result<(), String> {
        let export = import_from_file(&name.to_string())?;
        a.handle_response_base(export).map_err(|e| e.to_string())
    };
    if let Err(e) = export() {
        println!("导入错误：{}", ColoredString::from(e).red().bold());
    }
}
fn main() {
    let auth = Authenticator {
        inner: PinInner::new(),
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

