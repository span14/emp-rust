use emp_one_hot::{OneHotContext, Share, ShareMatrix, decode_matrix, outer_product};
use emp_tool::{
    Block,
    io_channel::{IOChannel, NetIO},
};
use rand::Rng;
use std::{env, io, thread};

fn send_share_matrix(io: &mut impl IOChannel, m: &ShareMatrix) -> io::Result<()> {
    for j in 0..m.cols() {
        for i in 0..m.rows() {
            io.send_block(&m[(i, j)].0)?;
        }
    }
    Ok(())
}

fn recv_share_matrix(io: &mut impl IOChannel, rows: usize, cols: usize) -> io::Result<ShareMatrix> {
    let mut m = ShareMatrix::new(rows, cols);
    for j in 0..cols {
        for i in 0..rows {
            m[(i, j)] = Share(io.recv_block()?);
        }
    }
    Ok(m)
}

fn main() {
    // Usage: cargo run -p emp-one-hot --example outer_product -- --party 1|2 [addr]
    let mut args = env::args().skip(1);
    let party: usize = args
        .next()
        .filter(|s| s == "--party")
        .and_then(|_| args.next())
        .expect("missing --party 1|2")
        .parse()
        .expect("invalid party");
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:23456".to_string());

    // Fixed example dimensions; adjust as needed.
    let n = 4usize;
    let m = 3usize;

    // Generator samples randomness and inputs, then streams them to the evaluator.
    let mut rng = rand::rng();
    let fixed_key = Block::from(rng.random::<u128>());
    let seed = Block::from(rng.random::<u128>());
    let x_bits: Vec<bool> = (0..n).map(|_| rng.random()).collect();
    let y_bits: Vec<bool> = (0..m).map(|_| rng.random()).collect();

    if party == 1 {
        let mut io = NetIO::new(true, &addr).expect("failed to listen");
        io.send_block(&fixed_key).unwrap();
        io.send_block(&seed).unwrap();
        io.send_bool_vec(&x_bits).unwrap();
        io.send_bool_vec(&y_bits).unwrap();

        let (out_g, delta) = {
            let mut ctx = OneHotContext::new_generator(&mut io, fixed_key, seed);
            let x_shares: Vec<Share> = x_bits.iter().map(|&b| ctx.bit(b)).collect();
            let y_shares: Vec<Share> = y_bits.iter().map(|&b| ctx.bit(b)).collect();
            let out = outer_product(&mut ctx, &x_shares, &y_shares).unwrap();
            (out, ctx.delta())
        };

        io.send_block(&delta).unwrap();
        send_share_matrix(&mut io, &out_g).unwrap();
        io.flush().unwrap();
        println!("Generator sent {}x{} garbled matrix", n, m);
    } else {
        // Allow the server to come up.
        thread::sleep(std::time::Duration::from_millis(50));
        let mut io = NetIO::new(false, &addr).expect("failed to connect");
        let fixed_key = io.recv_block().unwrap();
        let seed = io.recv_block().unwrap();
        let x_bits = io.recv_bool_vec(n).unwrap();
        let y_bits = io.recv_bool_vec(m).unwrap();

        let mut ctx = OneHotContext::new_evaluator(&mut io, fixed_key, seed);
        let x_shares: Vec<Share> = x_bits.iter().map(|&b| ctx.bit(b)).collect();
        let y_shares: Vec<Share> = y_bits.iter().map(|&b| ctx.bit(b)).collect();
        let out_e = outer_product(&mut ctx, &x_shares, &y_shares).unwrap();

        let delta = io.recv_block().unwrap();
        let out_g = recv_share_matrix(&mut io, n, m).unwrap();
        let decoded = decode_matrix(delta, &out_g, &out_e);

        println!("Decoded outer product:");
        for i in 0..n {
            for j in 0..m {
                print!("{} ", decoded.get(i, j) as u8);
            }
            println!();
        }
    }
}
