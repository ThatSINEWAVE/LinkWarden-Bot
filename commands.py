import discord
import requests
import json
from discord.commands import Option
from utils import get_whois_info, get_analysis_report, submit_to_urlscan, get_urlscan_result
from config import VIRUSTOTAL_API_KEY, ALLOWED_ROLE_IDS, SCAN_CHANNEL_ID, MAX_URL_LENGTH


async def checklink(ctx, link: Option(str, "Enter the link to check"), mode: Option(str, "Choose 'simple' or 'detailed' mode", choices=["simple", "detailed"]) = "simple"):
    # Check if the URL length exceeds the maximum allowed
    if len(link) > MAX_URL_LENGTH:
        await ctx.respond(f"The provided URL is too long to be processed safely. Maximum allowed length is {MAX_URL_LENGTH} characters.")
        print(f"[MANU-SCAN] URL={link}, SENT_BY_USER={ctx.author}, STATUS=DENIED, REASON=URL_TOO_LONG")
        return

    # Send an initial message indicating that the analysis is starting
    initial_response = await ctx.respond(f"🔍 Analysis in progress for `{link}` in **{mode} mode**. Please wait...")
    initial_message = await initial_response.original_response()
    print(f"[MANU-SCAN] URL={link}, SENT_BY_USER={ctx.author}, STATUS=IN_ANALYSIS, MODE={mode}, REASON=REQUESTED_BY_USER")

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

            embed = discord.Embed(title=f"Link Security Report - {mode.capitalize()} Mode", description=f"Detailed results for `{link}`:", color=0xFF0000 if malicious_count > 0 else 0x00FF00)
            embed.add_field(name="WHOIS Information", value=whois_info, inline=False)

            if urlscan_data:
                urlscan_info = f"URLScan.io Report: [View Report](https://urlscan.io/result/{urlscan_scan_uuid}/)"
                embed.add_field(name="Urlscan.io Analysis", value=urlscan_info, inline=False)
                if screenshot_url:
                    embed.set_image(url=screenshot_url)

            if mode == "simple":
                summary_text = "🔴 Caution: This link may be harmful." if malicious_count > 0 else "🟢 This link appears to be safe."
                embed.description = f"{summary_text}\n\nDetailed results for {link}:"
                if malicious_count > 0:
                    embed.add_field(name="⚠️ Malicious Detections (VirusTotal)", value=str(malicious_count), inline=False)
                warnings = [result for result in detailed_results if '🔴' in result or '🟡' in result][:10]
                if warnings:
                    embed.add_field(name="🚨 VirusTotal Warnings (Top 10)", value="\n".join(warnings), inline=False)
            else:  # Detailed mode
                embed.add_field(name="Malicious Detections (VirusTotal)", value=str(stats.get('malicious', 'N/A')), inline=True)
                embed.add_field(name="Harmless Detections (VirusTotal)", value=str(stats.get('harmless', 'N/A')), inline=True)
                embed.add_field(name="Suspicious Detections (VirusTotal)", value=str(stats.get('suspicious', 'N/A')), inline=True)
                embed.add_field(name="Undetected (VirusTotal)", value=str(stats.get('undetected', 'N/A')), inline=True)

                for i in range(0, len(detailed_results), 10):
                    embed.add_field(name=f"VirusTotal Detailed Results (Sample {i // 10 + 1})", value="\n".join(detailed_results[i:i + 10]), inline=False)

            # Update the initial message to indicate that the analysis is complete
            await initial_message.edit(content=f"✅ Analysis for `{link}` in **{mode} mode** was completed. Please check the message below.")
            print(f"[MANU-SCAN] URL={link}, SENT_BY_USER={ctx.author}, STATUS=COMPLETED, MODE={mode}, REASON=REQUESTED_BY_USER")

            # Send the analysis report embed
            await ctx.followup.send(embed=embed)
        else:
            # In case the analysis report couldn't be retrieved, update the message accordingly
            await initial_message.edit(content=f"❌ Failed to retrieve the analysis report for `{link}`. Please try again later.")
            print(f"[MANU-SCAN] URL={link}, SENT_BY_USER={ctx.author}, STATUS=FAILED, MODE={mode}, REASON=FAILED_TO_SUBMIT_URL")
    else:
        # If the link could not be submitted to VirusTotal, update the initial message
        await initial_message.edit(content=f"❌ Failed to submit the URL `{link}` to VirusTotal for scanning.")
        print(f"[MANU-SCAN] URL={link}, SENT_BY_USER={ctx.author}, STATUS=FAILED, MODE={mode}, REASON=FAILED_TO_RETRIEVE_REPORT")


async def checkhistory(ctx):
    # Check if the user has any of the allowed roles
    if not any(role.id in ALLOWED_ROLE_IDS for role in ctx.author.roles):
        await ctx.respond("You do not have the required role to use this command.")
        print(f"[HISTORY] REQUESTED_BY={ctx.author}, REQUESTED_IN={SCAN_CHANNEL_ID}, STATUS=DENIED, REASON=INVALID_ROLES")
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
                              color=0x3498db)
        print(f"[HISTORY] REQUESTED_BY={ctx.author}, REQUESTED_IN={SCAN_CHANNEL_ID}, STATUS=ALLOWED, REASON=VALID_ROLES")

        if sorted_links:
            # Limiting to show a maximum number of links due to embed field value limit
            max_links_to_show = 25
            links_shown = 0
            for link, count in sorted_links:
                if links_shown < max_links_to_show:
                    # Adding backticks around the link to make it unclickable
                    field_name = f"`{link}`"
                    if len(field_name) > 256:
                        field_name = field_name[:253] + "..."
                    embed.add_field(name=field_name, value=f"Link seen {count} times", inline=False)
                    links_shown += 1
                else:
                    break  # Stop adding more links to avoid hitting embed limits
            if links_shown < len(sorted_links):
                embed.set_footer(text=f"Showing the top {max_links_to_show} by usage")
        else:
            embed.description = "No links have been seen yet."

        # Send the embed message to the user
        await ctx.respond(embed=embed)
    except FileNotFoundError:
        await ctx.respond("The seen links history is currently empty.")


def setup_commands(bot, guild_ids):
    bot.slash_command(guild_ids=guild_ids, description="Checks the provided link for security threats.")(checklink)
    bot.slash_command(guild_ids=guild_ids, description="Check the history of scanned URLs")(checkhistory)
