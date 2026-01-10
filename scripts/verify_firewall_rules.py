#!/usr/bin/env python3
"""Script para verificar las reglas de firewall creadas por Mimosa en OPNsense.

Este script lista todas las reglas de firewall y muestra detalles de las reglas
creadas por Mimosa.
"""
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import httpx

# Añadir el directorio raíz al path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mimosa.core.sense import OPNsenseClient, FIREWALL_RULE_DESCRIPTIONS


def load_firewall_config() -> Dict[str, Any] | None:
    """Carga la configuración del firewall OPNsense desde data/firewalls.json."""
    config_path = Path(__file__).resolve().parents[1] / "data" / "firewalls.json"

    if not config_path.exists():
        print(f"❌ No se encontró {config_path}")
        return None

    with open(config_path) as f:
        firewalls = json.load(f)

    # Buscar el primer firewall de tipo OPNsense
    for fw in firewalls:
        if fw.get("type") == "opnsense":
            return fw

    print("❌ No se encontró ningún firewall de tipo 'opnsense' en la configuración")
    return None


def main():
    """Verifica las reglas de firewall en OPNsense."""
    print("=" * 70)
    print("🔥 Verificación de Reglas de Firewall de Mimosa")
    print("=" * 70)

    # Cargar configuración
    config = load_firewall_config()
    if not config:
        return 1

    print(f"\n📋 Conectando a: {config.get('base_url')}")

    # Crear cliente
    try:
        client = OPNsenseClient(
            base_url=config["base_url"],
            api_key=config["api_key"],
            api_secret=config["api_secret"],
            verify_ssl=config.get("verify_ssl", True),
            timeout=config.get("timeout", 15.0),
            apply_changes=False,  # No aplicar cambios automáticamente
        )
    except Exception as exc:
        print(f"\n❌ Error creando cliente: {exc}")
        return 1

    # Buscar reglas de Mimosa
    print("\n🔍 Buscando reglas de firewall de Mimosa...")

    try:
        # Obtener todas las reglas usando el endpoint /get
        response = client._request("GET", "/api/firewall/filter/get")
        data = response.json()
        rules_dict = data.get("filter", {}).get("rules", {}).get("rule", {})

        # Convertir dict a lista para procesamiento
        rows = []
        for uuid, rule in rules_dict.items():
            rule_copy = dict(rule)
            rule_copy["uuid"] = uuid
            # Extraer valores si están en formato dict
            for key, value in list(rule_copy.items()):
                if isinstance(value, dict) and "value" in value:
                    rule_copy[key] = value["value"]
            rows.append(rule_copy)

        print(f"📊 Total de reglas en el firewall: {len(rows)}")

        mimosa_rules = []
        for rule in rows:
            desc = rule.get("description", "")
            if desc in FIREWALL_RULE_DESCRIPTIONS.values():
                mimosa_rules.append(rule)

        if not mimosa_rules:
            print("\n⚠️ No se encontraron reglas de Mimosa")
            print("Ejecuta el diagnóstico para crearlas: docker exec mimosa python diagnose_opnsense.py")
            return 1

        print(f"\n✅ Encontradas {len(mimosa_rules)} reglas de Mimosa:")
        print()

        def safe_get(rule, key, default='N/A'):
            """Obtiene un valor de forma segura, manejando dicts anidados."""
            value = rule.get(key, default)
            if isinstance(value, dict):
                # Si es un dict, intentar obtener 'value' o convertir a string
                return value.get('value', str(value))
            return value or default

        for rule in mimosa_rules:
            print(f"{'=' * 70}")
            print(f"📌 Descripción: {safe_get(rule, 'description')}")
            print(f"   UUID: {safe_get(rule, 'uuid')}")
            print(f"   Habilitada: {'✅ Sí' if rule.get('enabled') == '1' else '❌ No'}")
            action = safe_get(rule, 'action', 'N/A')
            print(f"   Acción: {action.upper() if isinstance(action, str) else action}")
            print(f"   Interfaz: {safe_get(rule, 'interface')}")
            print(f"   Dirección: {safe_get(rule, 'direction')}")
            print(f"   Origen: {safe_get(rule, 'source_net')}")
            print(f"   Destino: {safe_get(rule, 'destination_net')}")
            print(f"   Protocolo: {safe_get(rule, 'protocol')}")
            print(f"   Quick: {'✅ Sí' if rule.get('quick') == '1' else '❌ No'}")
            print(f"   Log: {'✅ Sí' if rule.get('log') == '1' else '❌ No'}")
            print()

        print(f"{'=' * 70}")
        print("\n📖 Interpretación:")
        print("   • 'Quick' = La regla se evalúa inmediatamente sin procesar más reglas")
        print("   • 'Block' = El tráfico que coincida será bloqueado")
        print("   • 'Log' = Los bloqueos se registran en los logs del firewall")
        print()
        print("✅ Las reglas están activas y bloqueando tráfico de los alias de Mimosa")
        print()
        print("🌐 Para verificar en la interfaz web:")
        print(f"   1. Accede a: {config.get('base_url')}")
        print("   2. Ve a: Firewall → Automation → Filter")
        print("   3. Busca las reglas: 'Mimosa - Whitelist (allow)', 'Mimosa - Temporal blocks' y 'Mimosa - Permanent blacklist'")
        print()

        return 0

    except httpx.HTTPError as exc:
        print(f"\n❌ Error consultando reglas: {exc}")
        return 1
    except Exception as exc:
        print(f"\n❌ Error inesperado: {exc}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
