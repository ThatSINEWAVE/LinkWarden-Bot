import re
import discord
import asyncio
import requests
import json
from discord.ext import commands
from config import TOKEN, guild_ids
from commands import setup_commands
from utils import get_whois_info, get_analysis_report, submit_to_urlscan, get_urlscan_result
from config import VIRUSTOTAL_API_KEY, SCAN_CHANNEL_ID, ALLOWED_ROLE_IDS
from urllib.parse import urlparse

# Enable intents
intents = discord.Intents.default()
intents.messages = True
intents.guilds = True
intents.message_content = True

bot = commands.Bot(command_prefix="/", intents=intents)
link_queue = asyncio.Queue()

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
        parsed_url = urlparse(url)
        domain = parsed_url.netloc

        # Removing 'www.' prefix and port numbers from the domain
        domain = domain.replace('www.', '').split(':')[0]

        if domain not in trusted_domains:
            print(f"Adding {url} to the queue.")  # Debug print
            await link_queue.put((url, message))  # Modify this line to include the message
            update_seen_links(url)  # Update seen_links.json instead of adding to the set
        else:
            print(f"Skipping {url} as it's from a trusted domain.")  # Debug print

    await bot.process_commands(message)


async def checklink_scan(channel, link, message):
    with open('seen_links.json', 'r') as file:
        seen_links = json.load(file)

    # Check if the link is in seen_links and prepare the seen_text
    if link in seen_links:
        seen_text = f"Link was seen {seen_links[link]} times"
    else:
        seen_text = "Link was seen for the first time"

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
            await channel.send(embed=embed)
        else:
            await initial_message.edit(
                content=f"❌ Failed to retrieve the analysis report for `{link}`. Please try again later.")
    else:
        await initial_message.edit(content=f"❌ Failed to submit the URL `{link}` to VirusTotal for scanning.")


@bot.slash_command(description="Check the history of scanned URLs", guild_ids=guild_ids)
async def checkhistory(ctx):
    # Check if the user has any of the allowed roles
    if not any(role.id in ALLOWED_ROLE_IDS for role in ctx.author.roles):
        await ctx.respond("You do not have the required role to use this command.")
        return

    try:
        # Load seen links from file
        with open('seen_links.json', 'r') as file:
            seen_links = json.load(file)

        # Sort the links by count, from highest to lowest
        sorted_links = sorted(seen_links.items(), key=lambda item: item[1], reverse=True)

        # Prepare an embed message for nicer presentation
        embed = discord.Embed(title="Seen Links History",
                              description="This is the list of links that have been checked along with how many times they were seen, ordered from most to least seen.",
                              color=0x3498db)  # You can change the color

        if sorted_links:
            # Limiting to show a maximum number of links due to embed field value limit
            max_links_to_show = 25
            links_shown = 0
            for link, count in sorted_links:
                if links_shown < max_links_to_show:
                    # Adding backticks around the link to make it unclickable
                    embed.add_field(name=f"`{link}`", value=f"Link seen {count} times", inline=False)
                    links_shown += 1
                else:
                    break  # Stop adding more links to avoid hitting embed limits
            if links_shown < len(sorted_links):
                embed.set_footer(text=f"and more links... (showing only the first {max_links_to_show})")
        else:
            embed.description = "No links have been seen yet."

        # Send the embed message to the user
        await ctx.respond(embed=embed)
    except FileNotFoundError:
        await ctx.respond("The seen links history is currently empty.")


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
                embed.description = "\n".join([f"{idx + 1}. `{item[0]}`" for idx, item in enumerate(temp_list)])

                # Add a note about the cooldown in the footer
                embed.set_footer(text="Note: There is a 1-minute cooldown between scans.")

                # Truncate if exceeds max length limit
                if len(embed.description) > 4096 - len(embed.footer.text) - 2:  # Adjusting for footer length
                    embed.description = embed.description[:4093 - len(embed.footer.text) - 2] + "..."

                await scan_channel.send(embed=embed)
        else:
            print(f"Could not find the scan channel with ID {SCAN_CHANNEL_ID}")

        await asyncio.sleep(60)


status_messages = [
    "with dangerous links",
    "Project CW",
    "in the digital realm",
    "Chopper",
    "with viruses",
    "Poker with scammers",
    "Bug Hunt",
]

async def cycle_status():
    while True:
        for status in status_messages:
            game = discord.Game(status)
            await bot.change_presence(status=discord.Status.online, activity=game)
            await asyncio.sleep(20)  # Change the status every 20 seconds

@bot.event
async def on_ready():
    print(f'{bot.user} has connected to Discord!')
    await bot.loop.create_task(cycle_status())
    await bot.loop.create_task(process_link_queue())

# Setup commands
setup_commands(bot, guild_ids)

bot.run(TOKEN)
