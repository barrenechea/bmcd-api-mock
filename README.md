# bmcd-api-mock

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/license/MIT)

A mock of the exposed API from [bmcd](https://github.com/turing-machines/BMC-Firmware), intended for development and testing purposes.

## Description

`bmcd-api-mock` is a Go-based mock server that emulates the API endpoints and responses of the `bmcd` (BMC Daemon) component from the [BMC-Firmware](https://github.com/turing-machines/BMC-Firmware) project. It provides a lightweight and easy-to-use alternative for developers and testers who need to interact with the `bmcd` API without requiring the actual hardware setup.

The mock server simulates various API endpoints, including:

- Authentication
- Node power management
- USB mode configuration
- Firmware and flash state management
- System information retrieval
- Network state management
- Backup handling

## Getting Started

To run the `bmcd-api-mock` server, follow these steps:

1. Ensure you have Go installed on your system (version 1.22.2 or later).

2. Clone this repository:

   ```
   git clone https://github.com/barrenechea/bmcd-api-mock.git
   ```

3. Navigate to the project directory:

   ```
   cd bmcd-api-mock
   ```

4. Build and run the server:

   ```
   go run main.go
   ```

The server will start running on `http://localhost:4460`.

## Configuration

The `bmcd-api-mock` server uses the following configuration:

- Server port: `:4460`
- CORS max age: 300 seconds

## Usage

You can use any HTTP client (e.g., cURL, Postman) or your application code to interact with the mock server's API endpoints. The available endpoints and their responses mimic the behavior of the actual `bmcd` API.

For example, to retrieve system information:

```
curl http://localhost:4460/api/bmc?type=info
```

## Contributing

Contributions to `bmcd-api-mock` are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgements

- The `bmcd-api-mock` server is based on the API specification and behavior of the [bmcd](https://github.com/turing-machines/bmcd) component.
- Special thanks to the contributors of the [BMC-Firmware](https://github.com/turing-machines/BMC-Firmware) project for their work on the original `bmcd` component.
