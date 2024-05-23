This repository implements the code to benchmark the computation costs of the BLS threshold signature from the paper titled "Adaptively Secure BLS Threshold Signatures from DDH and co-CDH".
Paper link: https://eprint.iacr.org/2023/1553

### Code structure
The relevant implementations are part of the `src/` directory, and the directory has the following structure. 
```
    ├── README.md
    └── src
        ├── adaptive_bls.go             // implements new BLS threshold signatures
        ├── adaptive_bls_test.go        // implements the tests and benchmarking code for our scheme
        ├── boldyreva.go                // implements both Boldyreva-I (RO based DLEQ verification) and Boldyreva-II (pairing based verification)
        ├── boldyreva_test.go           // implmenets the tests and benchmarking code for Boldyreva-I and Boldyreva-II
        ├── utils.go                    // implements some common interfaces
        └── utils_test.go               // implements test case for our common funcitionalities
```

The code has been tested on a M2-pro Apple laptop with
`go version go1.21.5 darwin/arm64`

## Benchmarking of BLS threshold signatures
To benchmark the code go to the `src/` directory and run the following commmands.

### To benchmark boldyreva run
```go test -cpu 1 -benchmem -run=^$ -bench BenchmarkBLS```

Here `-cpu [NUM_CPU]` lets us configure the number of CPUs used for evaluating the schemes.

The benchmakr outputs the following results: 

1. For Boldyreva-I
    - `B1-pSign` measures the partial signing time
    - `B1-pVerify` measures the partial signature verification time
    - `[T]-B1-agg` measures the time to aggregate partial signatures from `T` signers. Our benchmark outputs numbers for a threshold of 64, 256, and 1024.
2. For Boldyreva-II
    - `B2-pSign` measures the partial signing time
    - `B2-pVerify` measures the partial signature verification time
    - `[T]-B2-agg` measures the time to aggregate partial signatures from `T` signers
3. Common
    - `[T]-verify` measures the cost to verify the final signatures with `T` signers. This is also applicable to our scheme.

### To benchmark adaptive BLS run
```go test -cpu 1 -benchmem -run=^$ -bench BenchmarkABLS```

The benchmakr outputs the following results:
1. Our scheme 
    - `ABLS-pSign` measures the partial signing time
    - `ABLS-pVerify` measures the partial signature verification time
    - `[T]-ABLS-agg` measures the time to aggregate partial signatures from `T` signers 