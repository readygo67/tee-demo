use std::io::{BufRead, BufReader, Write};

/// 在 SGX Enclave（TEE）中计算 x^3 + 5*y
fn compute(x: i64, y: i64) -> i64 {
    x.pow(3) + 5 * y
}

fn run_loop<R, W>(reader: &mut R, writer: &mut W)
where
    R: BufRead,
    W: Write,
{
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("读取输入失败: {err}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed == "quit" || trimmed == "exit" {
            break;
        }
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() != 2 {
            let _ = writeln!(writer, "ERROR=bad_input");
            let _ = writer.flush();
            continue;
        }

        let x: i64 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => {
                let _ = writeln!(writer, "ERROR=bad_x");
                let _ = writer.flush();
                continue;
            }
        };
        let y: i64 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => {
                let _ = writeln!(writer, "ERROR=bad_y");
                let _ = writer.flush();
                continue;
            }
        };

        let result = compute(x, y);
        let _ = writeln!(writer, "RESULT={result}");
        let _ = writer.flush();
    }
}

#[cfg(target_env = "sgx")]
fn main() {
    eprintln!("TEE daemon ready");
    let stream = std::net::TcpStream::connect("worker-host").expect("连接 worker-host 失败");
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut writer = stream;
    run_loop(&mut reader, &mut writer);
}
