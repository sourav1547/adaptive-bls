Benchmarking of BLS threshold signatures


### To benchmark boldyreva run
```go test -cpu 1 -benchmem -run=^$ -bench BenchmarkBoldyreva ```

### To benchmark adaptive BLS run
```go test -cpu 1 -benchmem -run=^$ -bench BenchmarkABLS ```