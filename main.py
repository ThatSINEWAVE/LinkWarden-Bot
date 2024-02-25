import discord
from discord.ext import commands
from config import TOKEN, guild_ids
from commands import setup_commands

bot = commands.Bot(command_prefix="/", intents=discord.Intents.default())

# Setup commands
setup_commands(bot, guild_ids)

bot.run(TOKEN)
