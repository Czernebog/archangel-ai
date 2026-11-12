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
        self.assertIn("VERSION 6.2.0", self.html)
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
        self.assertIn('VERSION 6.2.0', self.html)
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
        self.assertIn('keyboardOpen=focused&&covered>110', self.html)
        self.assertIn("grid-template-columns:minmax(0,1fr) auto", self.html)
        self.assertIn("max-height:min(20dvh,112px)", self.html)
        self.assertIn("VERSION 6.2.0", self.html)

    def test_html_language_and_accessibility(self):
        self.assertTrue(self.parser.has_lang)
        self.assertIn('aria-label="Отправить сообщение"', self.html)
        self.assertIn("setAttribute('aria-label','Остановить генерацию')", self.html)


if __name__ == "__main__":
    unittest.main()
