# LogAnalyzerAI
App IA

## Configuration, récupération et utilisation de la clé OpenAI (développement & production IIS)

---

## 1. Récupération de la clé OpenAI

Où trouver la clé :

- Se connecter à https://platform.openai.com/
- Aller dans "API Keys"
- Cliquer sur "Create new secret key"
- Copier la clé au format `sk-xxxxxxxxxxxxxxxx`

Avertissements importants :

- Ne jamais commit la clé dans Git.
- Ne jamais la mettre dans `appsettings.json` en clair dans le dépôt.
- Régénérer la clé si elle a été exposée.

---

## 2. Configuration en développement (User-Secrets)

Pour le développement local, utilisez `dotnet user-secrets` pour stocker la clé en dehors du code source. Exécutez ces commandes dans le dossier du projet (là où se trouve le fichier `.csproj`) :

```sh
dotnet user-secrets init
dotnet user-secrets set "OpenAI:ApiKey" "sk-xxxxxxxxxxxxxxxx"
```

Après avoir enregistré la clé avec `user-secrets`, l'application la lira via `IConfiguration["OpenAI:ApiKey"]` ou via `Environment.GetEnvironmentVariable("OPENAI_API_KEY")` si vous préférez définir une variable d'environnement locale.

---

## 3. Configuration pour production (IIS)

En production sous IIS, ne placez pas la clé dans le dépôt. Préférez une variable d'environnement ou un service de gestion de secrets (Azure Key Vault, HashiCorp Vault, etc.).

Options recommandées :

- Définir une variable d'environnement machine (recommandé) :
  - Ouvrir `Panneau de configuration` → `Système` → `Paramètres système avancés` → `Variables d'environnement`.
  - Ajouter `OPENAI_API_KEY` au niveau `Machine` (ou `User`) avec la valeur `sk-...`.
  - Redémarrer l'application / le pool d'applications IIS pour prendre en compte la nouvelle variable.

- Définir la variable d'environnement dans le fichier `web.config` (modèle ASP.NET Core hébergé sous IIS) — exemple :

```xml
<configuration>
  <system.webServer>
    <handlers>
      <!-- ... -->
    </handlers>
    <aspNetCore processPath="%LAUNCHER_PATH%" arguments="%LAUNCHER_ARGS%" stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout">
      <environmentVariables>
        <environmentVariable name="OPENAI_API_KEY" value="sk-xxxxxxxxxxxxxxxx" />
      </environmentVariables>
    </aspNetCore>
  </system.webServer>
</configuration>
```

  - Attention : ce fichier ne devrait pas contenir de secrets versionnés. Remplacez la valeur lors du déploiement via votre pipeline (CI/CD) ou utilisez une insertion sécurisée.

---

## 4. Bonnes pratiques

- Utiliser les variables d'environnement ou un coffre de secrets (Key Vault) en production.
- Limiter les permissions de la clé si possible et surveiller l'usage.
- Régénérer/rotater la clé régulièrement selon la politique de votre organisation.
- Ne partagez pas la clé dans des canaux non sécurisés (chat, email non chiffré, etc.).

---

Si vous souhaitez, je peux ajouter un exemple de pipeline CI/CD qui injecte la clé de façon sécurisée lors du déploiement vers IIS ou Azure App Service.
