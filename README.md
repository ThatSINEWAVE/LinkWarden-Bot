<div align="center">

# LinkWarden - Discord Link Scanner Bot

This Discord bot, designed for personal and community use, enhances server security by scrutinizing links shared within Discord channels. It leverages the VirusTotal API, WHOIS lookups, and urlscan.io scans to provide comprehensive real-time analysis, helping maintain a safe online environment for members.

</div>

## Features

- **Real-time Link Analysis**: Automatically checks links shared in Discord against the VirusTotal database, performs WHOIS lookups, and submits URLs to urlscan.io for scanning.
- **Comprehensive Security Reports**: Generates detailed reports including VirusTotal's analysis, domain registration details from WHOIS, and web page snapshots and security insights from urlscan.io.
- **Flexible Checking Modes**: Offers both a concise overview (Simple Mode) and detailed reports (Detailed Mode) to suit different user preferences.
- **Ease of use**: The bot will embed a screenshot of the link sent for checking right in the chat in both scanning modes, simple or detailed.
- **Automatic Link Scans**: The bot will look for links sent across the server and scan them automatically if they are not from a trusted domain.
- **Customizable Trusted Domain List** - With the addition of `trusted_domains.json` you can customize what domains should be scanned.
- **Role Specific Command** - The bot wont execute commands form users that do not have the specific role listed in the `config.py` file.
- **Link Source** - The bot will embed the message link where the scanned link was found in making moderation easier.
- **Link History** - The bot logs all links that are sent to be scanned and keeps them for future refrence
- **Customizable Status** - Custom status messages built-in.
- **Clean Console** - Custom print messages for every action and interaction with the bot.

<div align="center">

## ☕ [Support my work on Ko-Fi](https://ko-fi.com/thatsinewave)

</div>

## Getting Started

Before you can use the bot, you'll need to set it up with your Discord server and configure it with your API keys.

### Prerequisites

- A Discord account with administrative privileges on your server.
- Python 3.6 or higher.
- API keys for VirusTotal and urlscan.io (available from their respective websites).

<div align="center">

# [Join my discord server](https://discord.gg/2nHHHBWNDw)

</div>

### Installation

1. Clone this repository to your local machine.
2. Install the required dependencies by running `pip install -r requirements.txt`.
3. Create a `config.py` file in the same directory as your bot script ( or use the premade 'config.py' file ), and add your Discord Bot Token, VirusTotal API Key, URLScan.io API Key, guild ID(s), Moderator Role ID, and the ID of the channel where you want the output of auto link scans to go in the following format:

```python
TOKEN = 'your_discord_bot_token_here'
VIRUSTOTAL_API_KEY = 'your_virustotal_api_key_here'
URLSCAN_API_KEY = 'your_urlscan_io_api_key_here'
guild_ids = [your_guild_id_here]
SCAN_CHANNEL_ID = CHANNEL_WHERE_SCANS_SHOULD_GO
ALLOWED_ROLE_IDS = [MOD_ROLE_ID_GOES_HERE]
```
4. Run `main.py`

### Dependencies

This bot requires the following Python packages:
- py-cord
- requests
- python-whois
These can be installed using pip:

```python
pip install py-cord requests python-whois
```

Or you can install them using the requirements.txt file.

```python
pip install -r requirements.txt
```
## Usage

The bot is straightforward to use with a simple command structure. It supports the following command:

### Command Structure

`/checklink [LINK] [MODE]`

- **Simple Mode**: Provides a user-friendly summary including the safety status of the link, WHOIS domain registration summary, and a link to the urlscan.io report.

`/checklink https://example.com simple`

- **Detailed Mode**: Offers an exhaustive report with vendor-specific ratings from VirusTotal, detailed WHOIS information, and a comprehensive security report from urlscan.io.

`/checklink https://example.com detailed`

- **History**: Outputs a simple list of past links that were used for scans and keeps track of how many times each link was seen.

`/checklhistory`

### Modes Explained
- **SIMPLE**: Displays a concise embed with the top 10 warnings from VirusTotal, a summary of WHOIS information, and a link to the urlscan.io report.
- **DETAILED**: Presents a comprehensive report, marking each vendor with a color-coded dot as per the legend below, along with detailed WHOIS information and a urlscan.io security report.

### Status Dots Legend

- Harmless: 🟢
- Malicious: 🔴
- Suspicious: 🟡
- Undetected: ⚪

## Future Enhancements

- **Dashboard Integration**: Develop a web-based dashboard that provides an overview of past scans, including detailed results and statistics. This dashboard will offer insights into the types of links shared within the server and the bot's effectiveness in identifying threats, enhancing transparency and trust in the bot's capabilities.
- **Additional Scanning Integrations**: Expand the bot's scanning capabilities by integrating additional security tools and services. This expansion will provide more comprehensive coverage and protection against a wider range of online threats.
- **User Feedback System**: Implement a system for users to provide feedback on scan results, such as reporting false positives or missed threats. This feedback loop will help improve the bot's accuracy and effectiveness over time.

## Contributing

- Your contributions are welcome! Whether it's adding new features, improving documentation, or reporting bugs, please feel free to fork this repository and submit a pull request.

### Contributors

- **Cazaira** - helped refine and make the `trusted_domains.json` file stronger against false positives

## License

This project is open-sourced under the MIT License.
