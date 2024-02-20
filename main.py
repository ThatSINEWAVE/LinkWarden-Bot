import discord
import requests
from discord.ext import commands
from discord.commands import Option
import time

# Tokens and IDs
TOKEN = 'PRIVATE_DISCORD_BOT_TOKEN'
VIRUSTOTAL_API_KEY = 'API_KEY'
guild_ids = [YOUR_GUILD_ID]

# Set up bot command prefix
bot = commands.Bot(command_prefix="/", intents=discord.Intents.default())


def get_analysis_report(analysis_url, headers, retries=4, delay=15):
    """Attempt to retrieve the analysis report, with retries and delays to handle processing time."""
    for attempt in range(retries):
        report_response = requests.get(analysis_url, headers=headers)
        if report_response.status_code == 200:
            report = report_response.json()
            # Check if the analysis is completed
            if report['data']['attributes']['status'] == 'completed':
                return report
            else:
                print(f"Analysis not completed yet, attempt {attempt + 1}/{retries}. Retrying in {delay} seconds...")
                time.sleep(delay)
        else:
            # Immediate failure, no need to retry
            print(f"Failed to fetch the report, status code: {report_response.status_code}")
            break
    return None  # Return None if all retries fail or the report couldn't be fetched


@bot.slash_command(guild_ids=guild_ids, description="Checks the provided link for security threats.")
async def checklink(ctx,
                    link: Option(str, "Enter the link to check"),
                    mode: Option(str, "Choose 'simple' or 'detailed' mode", choices=["simple", "detailed"]) = "simple"):
    await ctx.defer()  # Acknowledge the interaction immediately

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    params = {'url': link}
    response = requests.post('https://www.virustotal.com/api/v3/urls', headers=headers, data=params)

    if response.status_code == 200:
        response_data = response.json()
        analysis_id = response_data['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        report = get_analysis_report(analysis_url, headers)
        if report:
            attributes = report['data']['attributes']
            stats = attributes['stats']
            malicious_count = stats.get('malicious', 0)

            # Emoji mapping for each category
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
                emoji = emoji_map.get(category, '❓')  # Use a question mark emoji if the category is unknown
                detailed_result = (f"{emoji} {vendor}: {category} "
                                   f"({result.get('result', 'No specific result')})")
                detailed_results.append(detailed_result)

            if mode == "simple":
                # Simple mode response
                summary_text = "🔴 Caution: This link may be harmful." if malicious_count > 0 else \
                    "🟢 This link appears to be safe."
                embed_color = 0xFF0000 if malicious_count > 0 else 0x00FF00
                embed = discord.Embed(title="Link Security Report - Simple Mode",
                                      description=f"{summary_text}\n\nDetailed results for {link}:", color=embed_color)

                if malicious_count > 0:
                    embed.add_field(name="⚠️ Malicious Detections", value=str(malicious_count), inline=False)

                # Warnings (Top 10)
                warnings = [result for result in detailed_results if '🔴' in result or '🟡' in result][
                           :10]  # Get top 10 non-clean results
                if warnings:
                    embed.add_field(name="🚨 Warnings (Top 10)", value="\n".join(warnings), inline=False)

                embed.set_footer(text="This is a simplified summary. For full details, use the 'detailed' mode.")
            else:
                # Detailed mode response
                embed = discord.Embed(title="Link Security Report - Detailed Mode",
                                      description=f"Detailed results for {link}:", color=0x00ff00)
                embed.add_field(name="Malicious Detections", value=str(stats.get('malicious', 'N/A')), inline=True)
                embed.add_field(name="Harmless Detections", value=str(stats.get('harmless', 'N/A')), inline=True)
                embed.add_field(name="Suspicious Detections", value=str(stats.get('suspicious', 'N/A')), inline=True)
                embed.add_field(name="Undetected", value=str(stats.get('undetected', 'N/A')), inline=True)

                if detailed_results:
                    for i in range(0, len(detailed_results), 10):
                        embed.add_field(name=f"Detailed Results (Sample {i // 10 + 1})",
                                        value="\n".join(detailed_results[i:i + 10]), inline=False)

            await ctx.followup.send(embed=embed)
        else:
            await ctx.followup.send("Failed to retrieve the analysis report from VirusTotal after several attempts.")
    else:
        await ctx.followup.send("Failed to submit the URL to VirusTotal for scanning.")


bot.run(TOKEN)
