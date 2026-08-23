_default:
    just --list

analyze *args:
    uv run analyze_seeds.py --output web/data.json {{args}}

serve *args: (analyze args)
    python3 -m http.server 8000 -d web
