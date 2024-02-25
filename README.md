# Discord Link Checker Bot

This Discord bot, designed for personal and community use, enhances server security by scrutinizing links shared within Discord channels. It leverages the VirusTotal API, WHOIS lookups, and urlscan.io scans to provide comprehensive real-time analysis, helping maintain a safe online environment for members.

## Features

- **Real-time Link Analysis**: Automatically checks links shared in Discord against the VirusTotal database, performs WHOIS lookups, and submits URLs to urlscan.io for scanning.
- **Comprehensive Security Reports**: Generates detailed reports including VirusTotal's analysis, domain registration details from WHOIS, and web page snapshots and security insights from urlscan.io.
- **Flexible Checking Modes**: Offers both a concise overview (Simple Mode) and detailed reports (Detailed Mode) to suit different user preferences.
- **Ease of use**: The bot will embed a screenshot of the link sent for checking right in the chat in both scanning modes, simple or detailed.

## Getting Started

Before you can use the bot, you'll need to set it up with your Discord server and configure it with your API keys.

### Prerequisites

- A Discord account with administrative privileges on your server.
- Python 3.6 or higher.
- API keys for VirusTotal and urlscan.io (available from their respective websites).

### Installation

1. Clone this repository to your local machine.
2. Install the required dependencies by running `pip install -r requirements.txt`.
3. Create a `config.py` file in the same directory as your bot script, and add your Discord Bot Token, VirusTotal API Key, urlscan.io API Key, and guild ID(s) in the following format:

```python
TOKEN = 'your_discord_bot_token_here'
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key_here'
URLSCAN_API_KEY = 'your_urlscan_io_api_key_here'
guild_ids = [your_guild_id_here]
```
4. Run `main.py`

## Dependencies

This bot requires the following Python packages:
- discord.py
- requests
- python-whois
These can be installed using pip:

```python
pip install discord.py requests python-whois
```

Or you can install them using the requirements.txt file.

```python
by running `pip install -r requirements.txt`
```
## Usage

The bot is straightforward to use with a simple command structure. It supports the following command:

### Command Structure

`/checklink [LINK] [MODE]`

- **Simple Mode**: Provides a user-friendly summary including the safety status of the link, WHOIS domain registration summary, and a link to the urlscan.io report.

`/checklink https://example.com simple`

- **Detailed Mode**: Offers an exhaustive report with vendor-specific ratings from VirusTotal, detailed WHOIS information, and a comprehensive security report from urlscan.io.

`/checklink https://example.com detailed`

### Modes Explained
- **SIMPLE**: Displays a concise embed with the top 10 warnings from VirusTotal, a summary of WHOIS information, and a link to the urlscan.io report.
- **DETAILED**: Presents a comprehensive report, marking each vendor with a color-coded dot as per the legend below, along with detailed WHOIS information and a urlscan.io security report.

## Status Dots Legend

- Harmless: 🟢
- Malicious: 🔴
- Suspicious: 🟡
- Undetected: ⚪

## Future Enhancements

- **Modular Codebase**: Refactor the bot's codebase to split functionalities into individual modules, making the code easier to maintain and extend. This modular approach will facilitate adding new features and integrations seamlessly.
- **Configurable Settings**: Introduce bot settings that server administrators can customize, such as enabling or disabling certain features and scanning modes. This flexibility will allow admins to tailor the bot's functionality to their server's specific needs and preferences.
- **Dashboard Integration**: Develop a web-based dashboard that provides an overview of past scans, including detailed results and statistics. This dashboard will offer insights into the types of links shared within the server and the bot's effectiveness in identifying threats, enhancing transparency and trust in the bot's capabilities.
- **Additional Scanning Integrations**: Expand the bot's scanning capabilities by integrating additional security tools and services. This expansion will provide more comprehensive coverage and protection against a wider range of online threats.
- **User Feedback System**: Implement a system for users to provide feedback on scan results, such as reporting false positives or missed threats. This feedback loop will help improve the bot's accuracy and effectiveness over time.

## Contributing
- Your contributions are welcome! Whether it's adding new features, improving documentation, or reporting bugs, please feel free to fork this repository and submit a pull request.

## License

This project is open-sourced under the MIT License.
