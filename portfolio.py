import pandas as pd
from datetime import datetime, timedelta

# =========================================================
# 1. Gerando dados fictícios de logs de acesso
# =========================================================

data = {
    'timestamp': [datetime.now() - timedelta(minutes=i) for i in range(100)],
    'user_id': ['admin', 'user1', 'admin', 'guest', 'admin', 'user2'] * 16 + ['admin']*4,
    'status': ['Success', 'Success', 'Failed', 'Failed', 'Failed', 'Success'] * 16 + ['Failed']*4,
    'ip_address': ['192.168.1.1', '192.168.1.10', '45.122.10.5', '192.168.1.15', '45.122.10.5', '10.0.0.1'] * 16 + ['45.122.10.5']*4,
    'country': ['Brazil', 'Brazil', 'North Korea', 'Brazil', 'North Korea', 'USA'] * 16 + ['North Korea']*4
}

df = pd.DataFrame(data)

# =========================================================
# 2. Análise de Segurança — Detecção de possível Brute Force
# Regra: Mais de X falhas vindas do mesmo IP
# =========================================================

LIMITE_FALHAS = 5

ataques = df[df['status'] == 'Failed'].groupby('ip_address').size()
ips_suspeitos = ataques[ataques > LIMITE_FALHAS]

print("\n--- ALERTA DE SEGURANÇA ---")

if not ips_suspeitos.empty:
    for ip, qtd in ips_suspeitos.items():
        print(f"IP suspeito: {ip} | Tentativas falhas: {qtd}")
else:
    print("Nenhum comportamento anômalo detectado.")


# =========================================================
# 3. Análise Geográfica (valoriza seu portfólio)
# =========================================================

paises_suspeitos = df[df['status'] == "Failed"]['country'].value_counts()

print("\nFalhas por país:")
print(paises_suspeitos)


# =========================================================
# 4. Exportando para CSV (Power BI / visualização)
# =========================================================

df.to_csv('logs_seguranca.csv', index=False)

print("\nArquivo logs_seguranca.csv exportado com sucesso.")
