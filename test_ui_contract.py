"""Static app smoke tests: accessibility, controls and regression guards."""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest


class UIParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = {}
        self.brain_buttons = []
        self.voice_buttons = []
        self.textareas = 0
        self.has_lang = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "html":
            self.has_lang = bool(attrs.get("lang"))
        if "id" in attrs:
            key = attrs["id"]
            self.ids[key] = self.ids.get(key, 0) + 1
        if tag == "button":
            if attrs.get("data-brain-mode"):
                self.brain_buttons.append((attrs["data-brain-mode"], attrs.get("aria-pressed")))
            if attrs.get("data-voice-preview"):
                self.voice_buttons.append(attrs["data-voice-preview"])
        if tag == "textarea":
            self.textareas += 1


class UIContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = Path("index.html").read_text("utf-8")
        cls.parser = UIParser()
        cls.parser.feed(cls.html)

    def test_unique_critical_controls(self):
        for id_ in (
            "chatInput", "sendButton", "clearChat", "messages", "sidebar",
            "mobileMenu", "voiceStart", "modelStatus", "bootScreen", "chatModelBadge"
        ):
            with self.subTest(id=id_):
                self.assertEqual(self.parser.ids.get(id_), 1)

    def test_only_russian_female_voice_choice(self):
        self.assertEqual(self.parser.voice_buttons, ["ru:female"])
        self.assertNotIn('data-voice-preview="ru:male"', self.html)
        self.assertNotIn('data-voice-preview="en:', self.html)
        self.assertNotIn('data-voice-preview="es:', self.html)
        self.assertIn('id="voiceRuFemaleName"', self.html)
        self.assertIn('archangel-62-voice-ui', self.html)
        self.assertIn("state.prefs.voiceRuGender='female'", self.html)
        self.assertIn("playNeuralVoice(text,'ru-RU','female')", self.html)
        self.assertIn("VERSION 6.7.0", self.html)
        self.assertNotIn('data-voice-use=', self.html)

    def test_response_mode_buttons_are_accessible(self):
        self.assertEqual({mode for mode, _ in self.parser.brain_buttons},
                         {"balanced", "deep"})
        self.assertTrue(all(pressed in ("true", "false")
                            for _, pressed in self.parser.brain_buttons))
        self.assertIn("function syncBrainMode()", self.html)

    def test_voice_has_single_device_fallback_and_neural_router(self):
        # A second speakDevice definition previously caused infinite recursion.
        self.assertEqual(len(re.findall(r"function speakDevice\(text,forcedLocale\)", self.html)), 1)
        self.assertIn("function speak(text,forcedLocale)", self.html)
        self.assertIn("playNeuralVoice(text,'ru-RU','female')", self.html)

    def test_no_external_script_or_frame_embedding(self):
        scripts = re.findall(r"<script\b[^>]*>", self.html, flags=re.I)
        self.assertGreater(len(scripts), 0)
        self.assertTrue(all(" src=" not in script.lower() for script in scripts))
        self.assertNotIn("<iframe", self.html.lower())

    def test_privacy_controls_and_session_purge(self):
        self.assertEqual(self.parser.ids.get("deleteAllChats"), 1)
        self.assertEqual(self.parser.ids.get("wipeData"), 1)
        self.assertIn("function resetChatMemory()", self.html)
        self.assertIn("state.chats=[];state.messages=[];state.activeChatId=null", self.html)
        self.assertIn("privacyChannel?.postMessage({kind:'all'})", self.html)
        self.assertIn("fetch('/api/purge'", self.html)
        self.assertIn("DELETE_ARCHANGEL_SESSION", self.html)
        self.assertNotIn("const previousWipe42=", self.html)

    def test_scroll_and_extended_composer(self):
        self.assertIn('archangel-52-scroll-compose', self.html)
        self.assertIn("chatCard.addEventListener('wheel'", self.html)
        self.assertIn("event.preventDefault()", self.html)
        self.assertIn("overflow-y:auto!important", self.html)
        self.assertIn("grid-template-rows:minmax(94px,auto)", self.html)
        self.assertIn("grid-column:1/-1!important", self.html)
        self.assertIn("input.style.height=Math.max(", self.html)

    def test_advanced_context_remains_bounded(self):
        self.assertIn("slice(-28)", self.html)
        self.assertIn("mode:deep?'deep':'balanced'", self.html)
        self.assertIn("Отличай доказанное от предположений.", self.html)

    def test_final_monochrome_release_and_loader(self):
        self.assertIn('archangel-six-finish', self.html)
        self.assertIn('ARCHANGEL 6.0', self.html)
        self.assertIn('VERSION 6.7.0', self.html)
        self.assertIn('color-scheme:dark', self.html)
        self.assertIn('focus-visible', self.html)

    def test_microphone_dictation_is_not_sent_without_confirming(self):
        self.assertIn('instance.interimResults=true', self.html)
        self.assertIn("input.dispatchEvent(new Event('input'", self.html)
        self.assertNotIn("},1150)", self.html)
        self.assertIn("Речь распознана. Проверь текст и нажми отправить.", self.html)
        self.assertIn("voiceWake=true;voiceActive=true;", self.html)

    def test_neural_voice_silences_microphone_during_playback(self):
        self.assertIn("const microphoneWasActive=voiceWake&&!!recognition", self.html)
        self.assertIn("voiceSpeaking=true", self.html)
        self.assertIn("audio.onended=()=>", self.html)
        self.assertIn("resumeMic();", self.html)

    def test_mobile_layout_and_keyboard_fit(self):
        self.assertIn('archangel-61-mobile-fit', self.html)
        self.assertIn('body.arch-keyboard-open .mobile-tabbar{display:none!important}', self.html)
        self.assertIn('visualViewport', self.html)
        self.assertIn('keyboardOpen=document.activeElement===input&&covered>110', self.html)
        self.assertIn("grid-template-columns:minmax(0,1fr) auto", self.html)
        self.assertIn("max-height:min(20dvh,112px)", self.html)
        self.assertIn("VERSION 6.7.0", self.html)

    def test_history_delete_erases_chats_and_action_history(self):
        self.assertIn('id="clearHistory" type="button">Удалить историю и все переписки', self.html)
        self.assertIn("$('clearHistory').onclick=()=>$('deleteAllChats')?.click()", self.html)
        self.assertIn("state.history=[];state.chats=[];state.messages=[];state.activeChatId=null", self.html)
        self.assertIn("privacyChannel?.postMessage({kind:'chats'})", self.html)
        self.assertIn('archangel-63-privacy-voice', self.html)

    def test_legacy_voice_controls_are_inert_and_hidden(self):
        self.assertIn('class="voice-panel-grid arch-legacy-voice-controls" hidden inert', self.html)
        self.assertIn('.arch-legacy-voice-controls[hidden]', self.html)
        self.assertEqual(self.parser.voice_buttons, ["ru:female"])

    def test_copy_button_is_small_and_aligned_to_right(self):
        self.assertIn('archangel-64-copy-right', self.html)
        self.assertIn('#page-chat .message.assistant .message-copy', self.html)
        self.assertIn('align-self:flex-end!important', self.html)
        self.assertIn('flex-direction:column!important', self.html)
        self.assertIn("button.textContent='⧉ Копировать'", self.html)
        self.assertIn("button.setAttribute('aria-label','Копировать ответ ARCHANGEL')", self.html)
        self.assertIn('VERSION 6.7.0', self.html)

    def test_mobile_drawer_has_no_redundant_close_button(self):
        self.assertNotIn('id="mobileClose"', self.html)
        self.assertNotIn("close.addEventListener('click',closeMenu)", self.html)
        self.assertIn("menu.onclick=()=>{if(drawer.classList.contains('open'))closeMenu();else openMenu();}", self.html)
        self.assertIn("drawer.inert=mobile&&!opened", self.html)
        self.assertIn("scrim.addEventListener('click',closeMenu)", self.html)
        self.assertIn("if(ev.key==='Escape'&&drawer.classList.contains('open'))", self.html)
        self.assertIn("go=function(page){originalGo(page);closeMenu();", self.html)
        self.assertIn('archangel-65-navigation', self.html)

    def test_no_other_assistant_brand_in_public_site(self):
        for name in ("index.html", "manifest.webmanifest", "sw.js"):
            with self.subTest(file=name):
                self.assertNotIn("chatgpt", Path(name).read_text("utf-8").lower())
        self.assertIn("ARCHANGEL AI", self.html)
        self.assertIn("VERSION 6.7.0", self.html)

    def test_ui_performance_size_and_unique_ids(self):
        # An explicit first-party HTML budget is measured in UTF-8 bytes.
        # Actual mobile INP/LCP require a real-device browser test.
        document_bytes = len(self.html.encode("utf-8"))
        duplicates = {name: count for name, count in self.parser.ids.items() if count != 1}
        self.assertEqual(duplicates, {}, f"Duplicate HTML IDs: {duplicates}")
        self.assertLess(document_bytes, 400_000, f"HTML size budget exceeded: {document_bytes}")
        self.assertGreater(len(self.parser.ids), 100)
        print(f"ARCHANGEL UI METRICS: HTML={document_bytes} bytes, IDs={len(self.parser.ids)}, duplicated=0")

    def test_copy_controls_are_batched_to_frames(self):
        self.assertIn("new MutationObserver(records=>", self.html)
        self.assertIn("if(dirty.size&&!copyFrame)copyFrame=requestAnimationFrame(flushCopy)", self.html)
        self.assertIn("if(node.isConnected)addCopyButtons(node)", self.html)
        self.assertIn("contextRemaining=48000", self.html)
        self.assertIn("Math.min(4500,contextRemaining)", self.html)

    def test_mobile_composer_never_overlaps_attachments_or_mic(self):
        self.assertIn('archangel-67-mobile-composer', self.html)
        self.assertIn('#page-chat .composer .compose-tools #attachButton', self.html)
        self.assertIn('#page-chat .composer .compose-tools #voiceStart', self.html)
        self.assertIn('grid-row:2!important', self.html)
        self.assertIn('max-height:76px!important', self.html)
        self.assertIn('min-height:42px!important', self.html)
        self.assertIn('--arch-visual-height', self.html)
        self.assertIn('visible=viewport?.height||window.innerHeight', self.html)
        self.assertIn("scheduleViewport", self.html)
        self.assertIn("input.style.height=Math.max(minimum,Math.min(input.scrollHeight,maximum))+'px'", self.html)
        self.assertIn("VERSION 6.7.0", self.html)

    def test_message_send_releases_composer_height(self):
        self.assertIn("document.body.classList.toggle('arch-keyboard-open',keyboardOpen)", self.html)
        self.assertIn("$('chatInput').dispatchEvent(new Event('input',{bubbles:true}))", self.html)
        self.assertIn("if(window.innerWidth>760)$('chatInput').focus()", self.html)

    def test_html_language_and_accessibility(self):
        self.assertTrue(self.parser.has_lang)
        self.assertIn('aria-label="Отправить сообщение"', self.html)
        self.assertIn("setAttribute('aria-label','Остановить генерацию')", self.html)


if __name__ == "__main__":
    unittest.main()
