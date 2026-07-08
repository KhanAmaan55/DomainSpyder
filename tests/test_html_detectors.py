"""Tests for HTML body-based technology detectors."""

from domainspyder.sources.tech.html_detectors import detect_cms, detect_frontend


class TestDetectFrontend:
    def test_react(self):
        body = '<div id="__next">App</div><script src="/_next/static/abc.js"></script>'
        result = detect_frontend(body)
        names = [r["name"] for r in result]
        assert "React" in names

    def test_angular(self):
        body = '<app-root ng-version="15.0.0"></app-root>'
        result = detect_frontend(body)
        names = [r["name"] for r in result]
        assert "Angular" in names

    def test_vue(self):
        body = '<div id="app" data-v-abc123>Hello</div><script>vue.js</script>'
        result = detect_frontend(body)
        names = [r["name"] for r in result]
        assert "Vue" in names

    def test_no_frameworks(self):
        body = "<html><body>Plain HTML</body></html>"
        result = detect_frontend(body)
        assert result == []

    def test_strong_platform_suppression(self):
        body = '<div id="__next">App</div>'
        result = detect_frontend(body, strong_platforms={"Wix"})
        # Score should be suppressed
        react = [r for r in result if r["name"] == "React"]
        if react:
            assert react[0]["score"] < 8

    def test_svelte(self):
        body = '<div data-svelte-h="abc">App</div>'
        result = detect_frontend(body)
        names = [r["name"] for r in result]
        assert "Svelte" in names

    def test_astro(self):
        body = '<astro-island>App</astro-island>'
        result = detect_frontend(body)
        names = [r["name"] for r in result]
        assert "Astro" in names

    def test_ionic(self):
        body = '<ion-app><ion-content>App</ion-content></ion-app>'
        result = detect_frontend(body)
        names = [r["name"] for r in result]
        assert "Ionic" in names

    def test_script_blob(self):
        body = "<html><body>Hello</body></html>"
        script_blob = "main.abc.js polyfills.def.js"
        result = detect_frontend(body, script_blob=script_blob)
        names = [r["name"] for r in result]
        assert "Angular" in names


class TestDetectCMS:
    def test_wordpress(self):
        html = '<html><body class="wp-content">Hello WordPress</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "WordPress" in names

    def test_wix(self):
        html = '<html><body>wix.com</body></html>'
        headers = {"X-Wix-Request-Id": "abc123"}
        result = detect_cms(html, headers)
        names = [r["name"] for r in result]
        assert "Wix" in names

    def test_shopify(self):
        html = '<html><body>cdn.shopify.com</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "Shopify" in names

    def test_drupal(self):
        html = '<html><body>/sites/default/files</body></html>'
        headers = {"X-Drupal-Cache": "HIT"}
        result = detect_cms(html, headers)
        names = [r["name"] for r in result]
        assert "Drupal" in names

    def test_joomla(self):
        html = '<html><body>/media/system/js/</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "Joomla" in names

    def test_webflow(self):
        html = '<html><body>webflow.io</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "Webflow" in names

    def test_squarespace(self):
        html = '<html><body>squarespace.com</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "Squarespace" in names

    def test_ghost(self):
        html = '<html><body>ghost.io</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "Ghost" in names

    def test_hubspot(self):
        html = '<html><body>hs-scripts.com</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "HubSpot" in names

    def test_magento(self):
        html = '<html><body>magento</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "Magento" in names

    def test_bigcommerce(self):
        html = '<html><body>bigcommerce</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "BigCommerce" in names

    def test_prestashop(self):
        html = '<html><body>prestashop /modules/ id_product</body></html>'
        result = detect_cms(html)
        names = [r["name"] for r in result]
        assert "PrestaShop" in names

    def test_no_cms(self):
        html = "<html><body>Plain HTML</body></html>"
        result = detect_cms(html)
        assert result == []

    def test_strong_platform_suppresses_others(self):
        html = '<html><body>wix.com</body></html>'
        headers = {"X-Wix-Request-Id": "abc"}
        result = detect_cms(html, headers)
        names = [r["name"] for r in result]
        assert "Wix" in names
        # WordPress should be suppressed due to Wix high score
        wp = [r for r in result if r["name"] == "WordPress"]
        assert len(wp) == 0

    def test_empty_html(self):
        result = detect_cms("")
        assert result == []
