
# Discord Link Checker - BOT

This is a simple Discord bot i wrote for personal use in my own servers and others that allows the staff team to check links sent by users within Discord.
The bot uses VirusTotal API to run the checks for each link that it gets




## Usage/Examples

The bot has a single command at the moment but i might update it in the future to include more commands

COMMAND:
/checklink [LINK] [MODE]

EXAMPLE: 
/checklink https://github.com/ simple

There are two modes, SIMPLE and DETAILED

SIMPLE = Brings up a user friendly embeded message that lists the top 10 warnings ( vendors that flagged the link as harmful ) and a bit more info

DETAILED = Outputs a full raport including every vendor marking each one with a colored DOT based on the list below
| TYPE             | DOT                                                                |
| ----------------- | ------------------------------------------------------------------ |
| harmless | 🟢
| malicious | 🔴
| suspicious | 🟡
| undetected | ⚪

