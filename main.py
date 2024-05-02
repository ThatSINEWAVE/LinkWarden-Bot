import re
import discord
import asyncio
import requests
import json
from discord.ext import commands
from config import TOKEN, guild_ids
from commands import setup_commands
from utils import get_whois_info, get_analysis_report, submit_to_urlscan, get_urlscan_result
from config import VIRUSTOTAL_API_KEY, SCAN_CHANNEL_ID, MAX_URL_LENGTH
from urllib.parse import urlparse

# Enable intents
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True

bot = commands.Bot(command_prefix="/", intents=intents)
link_queue = asyncio.Queue()
current_queued_links = set()

# Load trusted domains
with open('trusted_domains.json', 'r') as f:
    trusted_domains = json.load(f).get('trusted_domains', [])


# Function to read and update seen links
def update_seen_links(url):
    try:
        with open('seen_links.json', 'r') as file:
            seen_links = json.load(file)
    except FileNotFoundError:
        seen_links = {}

    seen_links[url] = seen_links.get(url, 0) + 1

    with open('seen_links.json', 'w') as file:
        json.dump(seen_links, file, indent=4)


@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    url_regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_regex, message.content)

    for url in urls:
        # Check if the URL length exceeds the maximum allowed
        if len(url) > MAX_URL_LENGTH:
            print(f"[QUEUE] URL={url}, SENT_BY={message.author}, STATUS=SKIPPED, REASON=URL_TOO_LONG")
            continue  # Skip processing this URL

        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        domain = domain.replace('www.', '').split(':')[0]

        # Immediately mark URL as seen to prevent race conditions
        if domain not in trusted_domains:
            if url not in current_queued_links:
                current_queued_links.add(url)  # Mark as queued before async operation

                try:
                    with open('seen_links.json', 'r') as file:
                        seen_links = json.load(file)
                except FileNotFoundError:
                    seen_links = {}

                seen_before = seen_links.get(url, 0) > 0

                if not seen_before or (seen_before):
                    print(f"[QUEUE] URL={url}, SENT_BY={message.author}, STATUS=ADDED, REASON=NOT_PROCESSED")
                    await link_queue.put((url, message))
                    update_seen_links(url)
                else:
                    current_queued_links.discard(url)  # Remove from set if not queuing
            else:
                print(f"[QUEUE] URL={url}, SENT_BY={message.author}, STATUS=SKIPPED, REASON=IN_PROCESS")
        else:
            print(f"[QUEUE] URL={url}, SENT_BY={message.author}, STATUS=SKIPPED, REASON=TRUSTED_DOMAIN")
            current_queued_links.discard(url)  # Ensure cleanup if not adding to queue

    await bot.process_commands(message)


async def checklink_scan(channel, link, message):
    # Check if the URL length exceeds the maximum allowed
    if len(link) > MAX_URL_LENGTH:
        print(f"[AUTO-SCAN] URL={link}, SENT_BY_USER={message.author}, STATUS=SKIPPED, REASON=URL_TOO_LONG")
        return  # Skip processing this URL

    with open('seen_links.json', 'r') as file:
        seen_links = json.load(file)

    # Check if the link is in seen_links and prepare the seen_text
    if link in seen_links:
        seen_text = f"Link was seen {seen_links[link]} times"
    else:
        seen_text = "Link was seen for the first time"

    mode = "simple"  # Set mode to simple
    initial_message = await channel.send(f"🔍 Starting analysis for `{link}` in **{mode} mode**. Please wait...")
    print(f"[AUTO-SCAN] URL={link}, SENT_BY_USER={message.author}, STATUS=IN_ANALYSIS, MODE={mode}, REASON=SENT_BY_USER")
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    params = {'url': link}
    vt_response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)

    if vt_response.status_code == 200:
        vt_data = vt_response.json()
        analysis_id = vt_data['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        vt_report = get_analysis_report(analysis_url, headers)

        domain = link.split('/')[2]
        whois_info = get_whois_info(domain)

        urlscan_scan_uuid = submit_to_urlscan(link)
        urlscan_data = None
        screenshot_url = None
        if urlscan_scan_uuid:
            urlscan_data = get_urlscan_result(urlscan_scan_uuid)
            if urlscan_data:
                screenshot_url = urlscan_data.get('task', {}).get('screenshotURL')

        if vt_report:
            attributes = vt_report['data']['attributes']
            stats = attributes['stats']
            malicious_count = stats.get('malicious', 0)

            emoji_map = {
                'harmless': '🟢',
                'malicious': '🔴',
                'suspicious': '🟡',
                'undetected': '⚪'
            }

            results = attributes['results']
            detailed_results = []
            for vendor, result in results.items():
                category = result['category']
                emoji = emoji_map.get(category, '❓')
                detailed_result = f"{emoji} {vendor}: {category} ({result.get('result', 'No specific result')})"
                detailed_results.append(detailed_result)

            warnings = [result for result in detailed_results if '🔴' in result or '🟡' in result][:10]
            warnings_text = "\n".join(warnings) if warnings else "No significant warnings."

            summary_text = "🔴 Caution: This link may be harmful." if malicious_count > 0 else "🟢 This link appears to be safe."
            embed = discord.Embed(title=f"Link Security Report - {mode.capitalize()} Mode",
                                  description=f"{summary_text}\n\nDetailed results for `{link}`.\nOriginal message: [Jump to message]({message.jump_url})\n{seen_text}",
                                  color=0xFF0000 if malicious_count > 0 else 0x00FF00)
            embed.add_field(name="WHOIS Information", value=whois_info, inline=False)

            if malicious_count > 0:
                embed.add_field(name="⚠️ Malicious Detections (VirusTotal)", value=str(malicious_count), inline=False)

            if warnings:
                embed.add_field(name="🚨 VirusTotal Warnings (Top 10)", value=warnings_text, inline=False)

            if urlscan_data:
                urlscan_info = f"URLScan.io Report: [View Report](https://urlscan.io/result/{urlscan_scan_uuid}/)"
                embed.add_field(name="Urlscan.io Analysis", value=urlscan_info, inline=False)
                if screenshot_url:
                    embed.set_image(url=screenshot_url)

            await initial_message.edit(
                content=f"✅ Analysis for `{link}` in **{mode} mode** was completed. Please check the message below.")
            print(f"[AUTO-SCAN] URL={link}, SENT_BY_USER={message.author}, STATUS=COMPLETED, MODE={mode}")
            await channel.send(embed=embed)
        else:
            await initial_message.edit(
                content=f"❌ Failed to retrieve the analysis report for `{link}`. Please try again later.")
            print(f"[AUTO-SCAN] URL={link}, SENT_BY_USER={message.author}, STATUS=FAILED, MODE={mode}, REASON=FAILED_TO_RETRIEVE_REPORT")
    else:
        await initial_message.edit(content=f"❌ Failed to submit the URL `{link}` to VirusTotal for scanning.")
        print(f"[AUTO-SCAN] URL={link}, SENT_BY_USER={message.author}, STATUS=FAILED, MODE={mode}, REASON=FAILED_TO_SUBMIT_URL")


async def process_link_queue():
    while True:
        link, message = await link_queue.get()

        # Use SCAN_CHANNEL_ID from the config
        scan_channel = bot.get_channel(SCAN_CHANNEL_ID)

        if scan_channel:
            await checklink_scan(scan_channel, link, message)
            # Use discard instead of remove to avoid KeyError
            current_queued_links.discard(link)

            # Check the size of the queue after the scan is completed
            if link_queue.qsize() > 0:
                # Access the queue's internal storage to read items without removing them
                temp_list = list(link_queue._queue)

                embed = discord.Embed(title="Current Link Queue", color=0x00FF00)
                embed.description = "\n".join([f"{idx + 1}. `{item[0]}`" for idx, item in enumerate(temp_list)])
                embed.set_footer(text="Note: There is a 1-minute cooldown between scans.")

                # Truncate if exceeds max length limit
                if len(embed.description) > 4096 - len(embed.footer.text) - 2:
                    embed.description = embed.description[:4093 - len(embed.footer.text) - 2] + "..."

                await scan_channel.send(embed=embed)
        else:
            print(f"[ERROR] STATUS=FAILED, REASON=CHANNEL_{SCAN_CHANNEL_ID}_COULD_NOT_BE_FOUND")

        await asyncio.sleep(60)


async def cycle_status_messages():
    status_messages = [
        discord.Game(name="with dangerous links"),
        discord.Activity(type=discord.ActivityType.listening, name="your conversations"),
        discord.Game(name="Project CW"),
        discord.Activity(type=discord.ActivityType.watching, name="your chat"),
        discord.Game(name="with viruses"),
        discord.Activity(type=discord.ActivityType.competing, name="tournaments"),
        discord.Game(name="dead"),
        discord.Activity(type=discord.ActivityType.listening, name="PCW Menu Music"),
        discord.Game(name="poker with scammers"),
        discord.Activity(type=discord.ActivityType.watching, name="#cw-discussion"),
        discord.Game(name="with fire"),
        discord.Activity(type=discord.ActivityType.competing, name="leaderboard"),
        discord.Game(name="with source code"),
        discord.Activity(type=discord.ActivityType.listening, name="your feedback"),
        discord.Game(name="*Bug Hunting*"),
        discord.Activity(type=discord.ActivityType.watching, name="scammers"),
        discord.Game(name="hide and seek"),
        discord.Activity(type=discord.ActivityType.competing, name="the chat"),
        discord.Game(name="with APIs"),
        discord.Activity(type=discord.ActivityType.listening, name="podcasts"),
        discord.Game(name="Brimstone"),
        discord.Activity(type=discord.ActivityType.watching, name="out for NSFW Servers"),
        discord.Game(name="nothing, im a bot"),
        discord.Activity(type=discord.ActivityType.competing, name="life"),
        discord.Game(name="with keyboard"),
        discord.Activity(type=discord.ActivityType.listening, name="SINEWAVE"),
        discord.Game(name="<REDACTED>"),
        discord.Activity(type=discord.ActivityType.watching, name="#off-topic"),
        discord.Game(name="with leaks"),
        discord.Activity(type=discord.ActivityType.competing, name="time"),
    ]

    while True:
        for status in status_messages:
            await bot.change_presence(activity=status)
            await asyncio.sleep(30)  # Adjust the sleep time as needed


@bot.event
async def on_ready():
    print(f'[BOT] BOT={bot.user}, STATUS=CONNECTED')
    asyncio.create_task(process_link_queue())
    asyncio.create_task(cycle_status_messages())


# Setup commands
setup_commands(bot, guild_ids)

bot.run(TOKEN)
