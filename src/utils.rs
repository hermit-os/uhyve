use error::*;

pub fn parse_mem(mem: &str) -> Result<usize> {
    let (num, postfix): (String, String) = mem.chars().partition(|&x| x.is_numeric());
    let num = num.parse::<usize>().map_err(|_| Error::ParseMemory)?;

    let factor = match postfix.as_str() {
        "E" | "e" => 1 << 60 as usize,
        "P" | "p" => 1 << 50 as usize,
        "T" | "t" => 1 << 40 as usize,
        "G" | "g" => 1 << 30 as usize,
        "M" | "m" => 1 << 20 as usize,
        "K" | "k" => 1 << 10 as usize,
        _ => return Err(Error::ParseMemory)
    };

    Ok(num*factor)
}
