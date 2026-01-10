#!/usr/bin/env python3
"""Script de diagnóstico para probar funciones de OPNsense.

Carga la configuración desde data/firewalls.json y prueba todas
las funciones disponibles del cliente OPNsense.
"""
import json
import sys
from pathlib import Path
from typing import Any, Dict

import httpx

# Añadir el directorio raíz al path
sys.path.insert(0, str(Path(__file__).parent))

from mimosa.core.sense import OPNsenseClient


def load_firewall_config() -> Dict[str, Any] | None:
    """Carga la configuración del firewall OPNsense desde data/firewalls.json."""
    config_path = Path(__file__).parent / "data" / "firewalls.json"

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


def test_connection(client: OPNsenseClient) -> bool:
    """Prueba la conectividad básica con OPNsense."""
    print("\n🔍 Probando conectividad...")
    try:
        client.check_connection()
        print("✅ Conexión exitosa")
        return True
    except httpx.HTTPError as exc:
        print(f"❌ Error de conexión: {exc}")
        return False


def test_get_status(client: OPNsenseClient) -> Dict[str, Any]:
    """Obtiene el estado del firewall y los alias."""
    print("\n🔍 Obteniendo estado del firewall...")
    try:
        status = client.get_status()
        print(f"✅ Estado obtenido:")
        print(f"   - Disponible: {status.get('available')}")
        print(f"   - Alias listo: {status.get('alias_ready')}")
        print(f"   - Alias creado: {status.get('alias_created')}")
        print(f"   - Cambios aplicados: {status.get('applied_changes')}")

        if "alias_details" in status:
            print(f"   - Detalles de alias:")
            for alias_type, details in status["alias_details"].items():
                print(f"     * {alias_type}: {details['name']} (creado: {details['created']})")

        if "ports_alias_status" in status:
            print(f"   - Estado de alias de puertos:")
            for protocol, details in status["ports_alias_status"].items():
                print(f"     * {protocol}: listo={details['ready']}, creado={details['created']}")

        return status
    except Exception as exc:
        print(f"❌ Error obteniendo estado: {exc}")
        return {}


def test_block_unblock_ip(client: OPNsenseClient, test_ip: str = "198.51.100.99") -> bool:
    """Prueba bloquear y desbloquear una IP."""
    print(f"\n🔍 Probando bloqueo/desbloqueo de IP {test_ip}...")

    try:
        # Bloquear IP
        print(f"   Bloqueando {test_ip}...")
        client.block_ip(test_ip, "Prueba de diagnóstico")

        # Verificar que está bloqueada
        table = client.list_table()
        if test_ip in table:
            print(f"   ✅ IP bloqueada correctamente")
        else:
            print(f"   ⚠️ IP no aparece en la tabla después de bloquear")
            print(f"   Contenido de tabla: {table}")

        # Desbloquear IP
        print(f"   Desbloqueando {test_ip}...")
        client.unblock_ip(test_ip)

        # Verificar que fue desbloqueada
        table = client.list_table()
        if test_ip not in table:
            print(f"   ✅ IP desbloqueada correctamente")
            return True
        else:
            print(f"   ⚠️ IP aún aparece en la tabla después de desbloquear")
            return False

    except Exception as exc:
        print(f"   ❌ Error durante bloqueo/desbloqueo: {exc}")
        # Intentar limpiar
        try:
            client.unblock_ip(test_ip)
        except:
            pass
        return False


def test_blacklist_operations(client: OPNsenseClient, test_ip: str = "203.0.113.99") -> bool:
    """Prueba las operaciones de blacklist."""
    print(f"\n🔍 Probando operaciones de blacklist con {test_ip}...")

    try:
        # Añadir a blacklist
        print(f"   Añadiendo {test_ip} a blacklist...")
        client.add_to_blacklist(test_ip, "Prueba de diagnóstico - blacklist")

        # Verificar que está en blacklist
        blacklist = client.list_blacklist()
        if test_ip in blacklist:
            print(f"   ✅ IP añadida a blacklist correctamente")
        else:
            print(f"   ⚠️ IP no aparece en blacklist después de añadir")
            print(f"   Contenido de blacklist: {blacklist}")

        # Remover de blacklist
        print(f"   Removiendo {test_ip} de blacklist...")
        client.remove_from_blacklist(test_ip)

        # Verificar que fue removida
        blacklist = client.list_blacklist()
        if test_ip not in blacklist:
            print(f"   ✅ IP removida de blacklist correctamente")
            return True
        else:
            print(f"   ⚠️ IP aún aparece en blacklist después de remover")
            return False

    except Exception as exc:
        print(f"   ❌ Error durante operaciones de blacklist: {exc}")
        # Intentar limpiar
        try:
            client.remove_from_blacklist(test_ip)
        except:
            pass
        return False


def test_ports_operations(client: OPNsenseClient) -> bool:
    """Prueba las operaciones con alias de puertos."""
    print(f"\n🔍 Probando operaciones de puertos...")

    try:
        # Obtener puertos actuales
        print(f"   Obteniendo puertos actuales...")
        original_ports = client.get_ports()
        print(f"   ✅ Puertos actuales:")
        for protocol, ports in original_ports.items():
            print(f"     * {protocol}: {ports}")

        # Establecer puertos de prueba
        test_ports = [9999, 8888, 7777]
        print(f"   Estableciendo puertos de prueba TCP: {test_ports}...")
        client.set_ports_alias("tcp", test_ports)

        # Verificar puertos
        current_ports = client.get_ports()
        tcp_ports = current_ports.get("tcp", [])

        all_present = all(port in tcp_ports for port in test_ports)
        if all_present:
            print(f"   ✅ Puertos configurados correctamente")
        else:
            print(f"   ⚠️ Algunos puertos no están configurados")
            print(f"   Esperados: {test_ports}")
            print(f"   Actuales: {tcp_ports}")

        # Restaurar puertos originales
        print(f"   Restaurando puertos originales...")
        original_tcp = original_ports.get("tcp", [])
        client.set_ports_alias("tcp", original_tcp)
        print(f"   ✅ Puertos restaurados")

        return all_present

    except Exception as exc:
        print(f"   ❌ Error durante operaciones de puertos: {exc}")
        return False


def test_list_operations(client: OPNsenseClient) -> bool:
    """Prueba las operaciones de listado."""
    print(f"\n🔍 Probando operaciones de listado...")

    try:
        # Listar tabla temporal
        print(f"   Listando tabla temporal...")
        table = client.list_table()
        print(f"   ✅ Tabla temporal ({len(table)} entradas): {table[:5] if len(table) > 5 else table}")

        # Listar blacklist
        print(f"   Listando blacklist...")
        blacklist = client.list_blacklist()
        print(f"   ✅ Blacklist ({len(blacklist)} entradas): {blacklist[:5] if len(blacklist) > 5 else blacklist}")

        # Listar bloques (alias de list_table)
        print(f"   Listando bloques...")
        blocks = client.list_blocks()
        print(f"   ✅ Bloques ({len(blocks)} entradas)")

        return True

    except Exception as exc:
        print(f"   ❌ Error durante operaciones de listado: {exc}")
        return False


def test_apply_changes(client: OPNsenseClient) -> bool:
    """Prueba la aplicación de cambios."""
    print(f"\n🔍 Probando aplicación de cambios...")

    try:
        client.apply_changes()
        print(f"   ✅ Cambios aplicados correctamente")
        return True
    except Exception as exc:
        print(f"   ❌ Error aplicando cambios: {exc}")
        return False


def main():
    """Ejecuta todas las pruebas de diagnóstico."""
    print("=" * 70)
    print("🔥 Diagnóstico de funciones de OPNsense")
    print("=" * 70)

    # Cargar configuración
    config = load_firewall_config()
    if not config:
        print("\n❌ No se pudo cargar la configuración del firewall")
        return 1

    print(f"\n📋 Configuración cargada:")
    print(f"   Nombre: {config.get('name')}")
    print(f"   URL: {config.get('base_url')}")
    print(f"   Verificar SSL: {config.get('verify_ssl')}")
    print(f"   Timeout: {config.get('timeout')}s")
    print(f"   Aplicar cambios: {config.get('apply_changes')}")

    # Crear cliente
    try:
        client = OPNsenseClient(
            base_url=config["base_url"],
            api_key=config["api_key"],
            api_secret=config["api_secret"],
            verify_ssl=config.get("verify_ssl", True),
            timeout=config.get("timeout", 15.0),
            apply_changes=config.get("apply_changes", True),
        )
    except Exception as exc:
        print(f"\n❌ Error creando cliente: {exc}")
        return 1

    # Ejecutar pruebas
    results = {}

    results["connection"] = test_connection(client)
    if not results["connection"]:
        print("\n❌ No se pudo conectar al firewall. Verifica la configuración.")
        return 1

    results["status"] = test_get_status(client)
    results["list_operations"] = test_list_operations(client)
    results["block_unblock"] = test_block_unblock_ip(client)
    results["blacklist"] = test_blacklist_operations(client)
    results["ports"] = test_ports_operations(client)
    results["apply_changes"] = test_apply_changes(client)

    # Resumen
    print("\n" + "=" * 70)
    print("📊 Resumen de pruebas")
    print("=" * 70)

    passed = sum(1 for v in results.values() if v is True or (isinstance(v, dict) and v.get("available")))
    total = len(results)

    for test_name, result in results.items():
        if isinstance(result, dict):
            status = "✅" if result.get("available") else "❌"
        else:
            status = "✅" if result else "❌"
        print(f"{status} {test_name}")

    print(f"\nResultado: {passed}/{total} pruebas exitosas")

    if passed == total:
        print("\n🎉 ¡Todas las funciones están operativas!")
        return 0
    else:
        print(f"\n⚠️ {total - passed} prueba(s) fallaron")
        return 1


if __name__ == "__main__":
    sys.exit(main())
