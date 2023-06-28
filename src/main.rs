
fn str_to_state(string: &str) -> Vec<Vec<u8>> {
    let bytes = string.bytes().collect::<Vec<u8>>();
    return vec![
        vec![bytes[0], bytes[1], bytes[2], bytes[3]],
        vec![bytes[4], bytes[5], bytes[6], bytes[7]],
        vec![bytes[8], bytes[9], bytes[10], bytes[11]],
        vec![bytes[12], bytes[13], bytes[14], bytes[15]],
    ];
}

fn shift(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut state = state.clone();
    state[1].rotate_left(1);
    state[2].rotate_left(2);
    state[3].rotate_left(3);
    return state;
}

fn inv_shift(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut state = state.clone();
    state[3].rotate_right(3);
    state[2].rotate_right(2);
    state[1].rotate_right(1);
    return state;
}

fn add_round_key(state: &Vec<Vec<u8>>, key: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut state = state.clone();
    for state_index in 0..4 {
        for block_index in 0..4 {
            state[state_index][block_index] = state[state_index][block_index] ^ key[state_index][block_index];
        }
    }
    return state;
}

fn mix(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut state = state.clone();
    state.rotate_right(3);
    for state_index in 0..4 {
        for block_index in 0..4 {
            if block_index != 3 {
                state[state_index][block_index] = state[state_index][block_index] ^ state[state_index][block_index + 1];
            }
        }
    }
    return state;
}

fn inv_mix(state: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut state = state.clone();
    for state_index in 0..4 {
        // RANGE CANT COUNT BACKWARDS
        let mut block_index = 3;
        while block_index != 0 {
            if block_index != 0 {
                state[state_index][block_index - 1] = state[state_index][block_index - 1] ^ state[state_index][block_index];
            }
            block_index -= 1;
        }
    }
    state.rotate_left(3);
    return state;
}

fn encrypt(state: &Vec<Vec<u8>>, key: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut state = state.clone();
    state = add_round_key(&state, key);
    for _ in 1..100 {
        state = shift(&state);
        state = mix(&state);
        state = add_round_key(&state, key);
    }
    return state;
}

fn decrypt(state: &Vec<Vec<u8>>, key: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut state = state.clone();
    for _ in 1..100 {
        state = add_round_key(&state, key);
        state = inv_mix(&state);
        state = inv_shift(&state);
    }
    state = add_round_key(&state, key);
    return state;
}


fn main() {
    let plaintext = "hi do the griddy";
    let key = str_to_state("cydw eo2iwbd ypq");
    let state = str_to_state(plaintext);
    println!("Plaintext: {:?}", state);
    println!("Plaintext text: {}", plaintext);
    let encrypted = encrypt(&state, &key);
    let decrypted = decrypt(&encrypted, &key);
    println!("Encrypted: {:?}", encrypted);
    unsafe { println!("Encrypted text: {}", String::from_utf8_unchecked(encrypted.join(&0))); }
    println!("Decrypted: {:?}", decrypted);
    unsafe { println!("Decrypted text: {}", String::from_utf8_unchecked(decrypted.join(&0))); }
}



