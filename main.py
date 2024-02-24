import discord
import requests
from discord.ext import commands
from discord.commands import Option
import time
import whois
from config import TOKEN, VIRUSTOTAL_API_KEY, URLSCAN_API_KEY, guild_ids

bot = commands.Bot(command_prefix="/", intents=discord.Intents.default())


def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        whois_text = f"Domain: {domain}\n"
        if w.registrar:
            whois_text += f"Registrar: {w.registrar}\n"
        if w.creation_date:
            whois_text += f"Creation Date: {w.creation_date}\n"
        if w.expiration_date:
            whois_text += f"Expiration Date: {w.expiration_date}\n"
        return whois_text
    except Exception as e:
        print(f"Failed to fetch WHOIS info: {e}")
        return "WHOIS information could not be retrieved."


def get_analysis_report(analysis_url, headers, retries=4, delay=15):
    for attempt in range(retries):
        report_response = requests.get(analysis_url, headers=headers)
        if report_response.status_code == 200:
            report = report_response.json()
            if report['data']['attributes']['status'] == 'completed':
                return report
            else:
                print(f"Analysis not completed yet, attempt {attempt + 1}/{retries}. Retrying in {delay} seconds...")
                time.sleep(delay)
        else:
            print(f"Failed to fetch the report, status code: {report_response.status_code}")
            break
    return None


def submit_to_urlscan(link):
    headers = {'API-Key': URLSCAN_API_KEY, 'Content-Type': 'application/json'}
    data = {"url": link, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data)
    if response.status_code == 200:
        scan_uuid = response.json().get('uuid')
        return scan_uuid  # Return the uuid instead of the result URL
    else:
        print(f"Failed to submit to urlscan.io, status code: {response.status_code}")
        return None


def get_urlscan_result(scan_uuid, retries=4, delay=15):
    result_url = f'https://urlscan.io/api/v1/result/{scan_uuid}/'  # Construct the result URL using the uuid

    for attempt in range(retries):
        time.sleep(delay)  # Wait before checking if the scan is ready
        response = requests.get(result_url)
        if response.status_code == 200:
            scan_data = response.json()
            return scan_data
        else:
            print(f"Attempt {attempt + 1}/{retries}: Failed to fetch the scan result, status code: {response.status_code}")

    return None


@bot.slash_command(guild_ids=guild_ids, description="Checks the provided link for security threats.")
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
        if urlscan_scan_uuid:
            urlscan_data = get_urlscan_result(urlscan_scan_uuid)

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

            if mode == "simple":
                summary_text = "🔴 Caution: This link may be harmful." if malicious_count > 0 else "🟢 This link appears to be safe."
                embed_color = 0xFF0000 if malicious_count > 0 else 0x00FF00
                embed = discord.Embed(title="Link Security Report - Simple Mode", description=f"{summary_text}\n\nDetailed results for {link}:", color=embed_color)

                if malicious_count > 0:
                    embed.add_field(name="⚠️ Malicious Detections (VirusTotal)", value=str(malicious_count), inline=False)

                warnings = [result for result in detailed_results if '🔴' in result or '🟡' in result][:10]
                if warnings:
                    embed.add_field(name="🚨 VirusTotal Warnings (Top 10)", value="\n".join(warnings), inline=False)

                embed.add_field(name="WHOIS Information", value=whois_info, inline=False)

                if urlscan_data:
                    urlscan_info = f"URLScan.io Report: [View Report](https://urlscan.io/result/{urlscan_scan_uuid}/)"
                    embed.add_field(name="Urlscan.io Analysis", value=urlscan_info, inline=False)

                embed.set_footer(text="This is a simplified summary. For full details, use the 'detailed' mode. Always exercise caution.")
            else:
                embed = discord.Embed(title="Link Security Report - Detailed Mode", description=f"Detailed results for {link}:", color=0x00ff00)
                embed.add_field(name="Malicious Detections (VirusTotal)", value=str(stats.get('malicious', 'N/A')), inline=True)
                embed.add_field(name="Harmless Detections (VirusTotal)", value=str(stats.get('harmless', 'N/A')), inline=True)
                embed.add_field(name="Suspicious Detections (VirusTotal)", value=str(stats.get('suspicious', 'N/A')), inline=True)
                embed.add_field(name="Undetected (VirusTotal)", value=str(stats.get('undetected', 'N/A')), inline=True)

                if detailed_results:
                    for i in range(0, len(detailed_results), 10):
                        embed.add_field(name=f"VirusTotal Detailed Results (Sample {i // 10 + 1})", value="\n".join(detailed_results[i:i + 10]), inline=False)

                embed.add_field(name="WHOIS Information", value=whois_info, inline=False)

                if urlscan_data:
                    urlscan_info = f"URLScan.io Report: [View Report](https://urlscan.io/result/{urlscan_scan_uuid}/)"
                    embed.add_field(name="Urlscan.io Analysis", value=urlscan_info, inline=False)

            await ctx.followup.send(embed=embed)
        else:
            await ctx.followup.send("Failed to retrieve the analysis report from VirusTotal after several attempts.")
    else:
        await ctx.followup.send("Failed to submit the URL to VirusTotal for scanning.")

bot.run(TOKEN)
