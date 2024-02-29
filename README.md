
# Indicator of Comprimise Scanner

A CLI tool for scanning IP addresses using multiple API's. It allows users to specify IP addresses directly or through a file and perform scans using the VirusTotal service. Users can choose to display the scan results on the console or save them to a text file.

![Logo](https://media.kasperskydaily.com/wp-content/uploads/sites/93/2018/09/04085222/from-cubersecurity-to-cyber-defense.jpg)


## Installation

To run the project locally, follow these steps

1. Clone the project repository:

```bash
git clone https://link-to-project
```

2. Navigate to the project directory:

```bash
cd virustotal-ip-scanner
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Install dependencies:

```bash
python main.py --ip-address targets/ips.txt --virustotal-ip-scan

```
## Configuration

Before using the CLI, you need to obtain a VirusTotal API key and configure it. You can either provide the API key as a command-line argument or store it in a config.cfg file in the following format:

```txt
virustotal_api_key:YOUR_API_KEY_HERE
```
## Usage/Examples

To scan IP addresses using the VirusTotal service, execute the following command:

```bash
python main.py --ip-address targets/ips.txt --virustotal-ip-scan
```
You can also use the shorthand **-VPS** instead of **--virustotal-ip-scan**.


## Demo

www.youtube.com/thisisanexample


## Environment Variables

This project requires the following environment variables:

`API_KEY`: Your VirusTotal API key




## Features

- Scan IP addresses using VirusTotal service
- Display scan results or save them to a text file
- Configurable through command-line arguments or - configuration file


## Tech Stack
- **Python**
- **Requests** library for HTTP requests
- **Colorama** library for colored output

## Roadmap

- Support for additional scanning services besides VirusTotal
- Enhancement of error handling and input validation
- Improved documentation and examples


## Used By

This project is used by the following companies:

- BSC
- Company 2


## Support

For support, email luckgamer40@gmail.com

## License

[MIT](https://choosealicense.com/licenses/mit/)


## Feedback

If you have any feedback, please reach out to us at luckgamer40@gmail.com


## Frequently Asked Questions (FAQ)

#### 1. How do I obtain a VirusTotal API key?

You can obtain a VirusTotal API key by signing up for a free or paid account on the VirusTotal website. Once you've created an account, navigate to your profile settings to find your API key.

#### 2. an I use this tool to scan multiple IP addresses at once?

Yes, you can specify multiple IP addresses either directly as a comma-separated list or by providing a file containing the IP addresses separated by newline characters.
#### 3. What happens if I don't provide a VirusTotal API key?

If you don't provide a VirusTotal API key as a command-line argument, the tool will attempt to read the API key from a config.cfg file in the project directory. If the API key is not found in the file, the tool will prompt you to provide the API key manually.
#### 4. How do I save the scan results to a file?

You can use the -oT option followed by the desired output file name to save the scan results to a text file. If no output file name is specified, a default file name will be generated based on the current date and time
#### 5. Can I use this tool to scan domains or URLs?

Currently, the tool only supports scanning IP addresses. However, future updates may include support for scanning domains or URLs.

#### 6. Is there a limit to the number of IP addresses I can scan?


The number of IP addresses you can scan may be subject to rate limits imposed by the VirusTotal API or other factors. It's recommended to review the VirusTotal API documentation for any usage limits or restrictions.
#### 7. How can I contribute to the project?

If you'd like to contribute to the project, you can submit bug reports, feature requests, or pull requests on the project's GitHub repository. Your contributions are welcome and appreciated!
#### 8. I encountered an error while using the tool. What should I do?

If you encounter any errors or issues while using the tool, please check the documentation and FAQ section first for any troubleshooting steps. If the problem persists, feel free to reach out to the project maintainers for assistance.
#### 9. Can I use this tool for commercial purposes?

Yes, you can use this tool for both personal and commercial purposes, subject to the terms of the MIT License. Please refer to the project's license file for more information.
#### Where can I find more information about the project?

You can find more information about the project, including documentation, usage examples, and updates, on the project's GitHub repository. Feel free to explore the repository and reach out to the project maintainers for any additional queries.

This FAQ section aims to address common questions and concerns about the project. If you have any further questions or inquiries, don't hesitate to reach out to the project maintainers for assistance.
