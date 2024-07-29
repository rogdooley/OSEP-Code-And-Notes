    ### Instructions to Compile and Run

1. **Install OpenSSL development libraries**:
   On Ubuntu, you can install them using:
   ```sh
   sudo apt-get install libssl-dev
   ```

2. **Compile the Encoder Program**:
   ```sh
   gcc -o encoder encoder.c -lssl -lcrypto
   ```

3. **Run the Encoder Program**:
   ```sh
   ./encoder
   ```

4. **Compile the Decoder and Executor Program**:
   ```sh
   gcc -o decoder decoder.c -lssl -lcrypto
   ```

5. **Run the Decoder and Executor Program**:
   ```sh
   ./decoder
   ```

