import re
import discord
import asyncio
import requests
import json
from discord.ext import commands
from config import TOKEN, guild_ids
from commands import setup_commands
from utils import get_whois_info, get_analysis_report, submit_to_urlscan, get_urlscan_result
from config import VIRUSTOTAL_API_KEY, SCAN_CHANNEL_ID
from urllib.parse import urlparse

# Enable intents
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True

bot = commands.Bot(command_prefix="/", intents=intents)
link_queue = asyncio.Queue()
seen_links = set()

# Load trusted domains
with open('trusted_domains.json', 'r') as f:
    trusted_domains = json.load(f).get('trusted_domains', [])


@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    url_regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_regex, message.content)

    for url in urls:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Removing 'www.' prefix and port numbers from the domain
        domain = domain.replace('www.', '').split(':')[0]

        if domain not in trusted_domains and url not in seen_links:
            print(f"Adding {url} to the queue.")  # Debug print
            await link_queue.put((url, message))  # Modify this line to include the message
            seen_links.add(url)  # Add the link to the set of seen links
        else:
            print(f"Skipping {url} as it's already seen or from a trusted domain.")  # Debug print

    await bot.process_commands(message)


async def checklink_scan(channel, link, message):  # Include the message parameter
    mode = "simple"  # Set mode to simple

    initial_message = await channel.send(f"🔍 Starting analysis for `{link}` in **{mode} mode**. Please wait...")

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
                                  description=f"{summary_text}\n\nDetailed results for `{link}`.\nOriginal message: [Click here]({message.jump_url})",
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

            await initial_message.edit(content=f"✅ Analysis for `{link}` in **{mode} mode** was completed. Please check the message below.")
            await channel.send(embed=embed)
        else:
            await initial_message.edit(content=f"❌ Failed to retrieve the analysis report for `{link}`. Please try again later.")
    else:
        await initial_message.edit(content=f"❌ Failed to submit the URL `{link}` to VirusTotal for scanning.")


async def process_link_queue():
    while True:
        link, message = await link_queue.get()  # Modify this line to unpack message

        # Use SCAN_CHANNEL_ID from the config
        scan_channel = bot.get_channel(SCAN_CHANNEL_ID)

        if scan_channel:
            await checklink_scan(scan_channel, link, message)  # Pass the message here

            # Check the size of the queue after the scan is completed
            if link_queue.qsize() > 0:  # Check if there are more links in the queue
                # Access the queue's internal storage to read items without removing them
                temp_list = list(link_queue._queue)

                embed = discord.Embed(title="Current Link Queue", color=0x00FF00)
                embed.description = "\n".join([f"{idx + 1}. `{item[0]}`" for idx, item in enumerate(temp_list)])  # Modify to access link

                # Add a note about the cooldown in the footer
                embed.set_footer(text="Note: There is a 1-minute cooldown between scans.")

                # Truncate if exceeds max length limit
                if len(embed.description) > 4096 - len(embed.footer.text) - 2:  # Adjusting for footer length
                    embed.description = embed.description[:4093 - len(embed.footer.text) - 2] + "..."

                await scan_channel.send(embed=embed)
        else:
            print(f"Could not find the scan channel with ID {SCAN_CHANNEL_ID}")

        await asyncio.sleep(60)  # 1-minute delay before processing the next link


@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    await bot.loop.create_task(process_link_queue())

# Setup commands
setup_commands(bot, guild_ids)

bot.run(TOKEN)
