#!/usr/bin/env python3

# builtin-imports
from __future__ import annotations
from datetime import datetime
import sys
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

# Third-party imports
import rich_click as click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress
from rich.table import Table
from rich.text import Text

# Local imports
import findcrypt4



@click.group(context_settings={'help_option_names': ['-h', '--help']})
@click.version_option(version=findcrypt4.__version__, message='%(version)s')
def main():
    pass

@main.command(name="list")
def list():
    """ List rule files """
    console = Console()

    table = Table(show_header=True)
    table.add_column("Creation Date", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("#rules", justify="right")

    for file in findcrypt4.RULES_DIR.iterdir():
        # Get creation date
        stat = file.stat()
        date_time = datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")
        rule_nb = sum([x.startswith("rule") for x in file.read_text().splitlines()])
        table.add_row(date_time, file.name, str(rule_nb))

    console.print(table)



@main.command(name="add-rule")
@click.argument('file', type=click.Path(exists=True), nargs=-1)
def add_rules(file: tuple[str]):
    """ Add rule files """
    console = Console()
    for f in file:
        res = findcrypt4.add_rule(f)
        r, color = ("OK", "green") if res else ("FAIL", "red")
        text = Text(f"{Path(f).name}: ")
        text.append(r, style=f"bold {color}")
        console.print(text)


@main.command(name="search")
@click.argument('file', type=click.Path(exists=True))
def search(file: str):
    """ Add rule files """
    console = Console()

    res = findcrypt4.file_search(file)
    if not res:
        console.print(Text("NO MATCH", style="bold red"))
        sys.exit(1)

    table = Table(show_header=True)
    kind = "Address" if isinstance(res[0], findcrypt4.ExeCryptoMatch) else "Offset"
    table.add_column(kind)
    table.add_column("File")
    table.add_column("Rule Name")
    table.add_column("String")
    table.add_column("Value")

    for match in res:
        off = str(match.offset) if kind == "Offset" else f"{match.address:#08x}"
        table.add_row(off, match.namespace, match.rule, match.identifier, repr(match.data[:10]))

    console.print(table)
