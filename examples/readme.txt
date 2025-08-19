# Disclaimer

⚠️ **Important Notice**

Many of the configuration snippets and tools provided here in the examples folder are **not native Nginx modules or features**.  
They rely on advanced configurations, external tools (like `bgpq4` or `jq`), or custom build options that may not exist in stable/production-grade environments.

I run a lot of these examples in **development, Debian testing/unstable, or custom test environments**.  
Some of this code may never make it into a normal production system.  

- ✅ Other scripts I share are used in **production** and are stable.  
- ⚠️ These Anthropic-specific detection examples should be treated as **experimental** and **tested in a dev environment first**.  
- 🚫 Do not drop them blindly into production without validation, as unexpected behavior could occur.

Always:
1. Test changes in a **non-production environment**.
2. Validate with `nginx -t` before reloading.
3. Monitor logs and traffic after applying.

Use this README as a **learning reference**, not a guaranteed production-ready configuration.
