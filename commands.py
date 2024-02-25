import discord
import requests
from discord.commands import Option
from utils import get_whois_info, get_analysis_report, submit_to_urlscan, get_urlscan_result
from config import VIRUSTOTAL_API_KEY


async def checklink(ctx, link: Option(str, "Enter the link to check"), mode: Option(str, "Choose 'simple' or 'detailed' mode", choices=["simple", "detailed"]) = "simple"):
    await ctx.defer()
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    params = {'url': link}
    vt_response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)

    if vt_response.status_code == 200:
        vt_data = vt_response.json()
        analysis_id = vt_data['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        vt_report = get_analysis_report(analysis_url, headers)

        domain = link.split('/')[2]  # Extract the domain from the URL
        whois_info = get_whois_info(domain)  # Perform the WHOIS lookup

        # Submit the URL to urlscan.io and wait for the scan to complete
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

            embed = discord.Embed(title=f"Link Security Report - {mode.capitalize()} Mode", description=f"Detailed results for {link}:", color=0xFF0000 if malicious_count > 0 else 0x00FF00)
            embed.add_field(name="WHOIS Information", value=whois_info, inline=False)

            if urlscan_data:
                urlscan_info = f"URLScan.io Report: [View Report](https://urlscan.io/result/{urlscan_scan_uuid}/)"
                embed.add_field(name="Urlscan.io Analysis", value=urlscan_info, inline=False)
                if screenshot_url:
                    embed.set_image(url=screenshot_url)  # Add the screenshot from urlscan.io

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

            await ctx.followup.send(embed=embed)
        else:
            await ctx.followup.send("Failed to retrieve the analysis report from VirusTotal after several attempts.")
    else:
        await ctx.followup.send("Failed to submit the URL to VirusTotal for scanning.")


def setup_commands(bot, guild_ids):
    bot.slash_command(guild_ids=guild_ids, description="Checks the provided link for security threats.")(checklink)
