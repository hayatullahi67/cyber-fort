import React, { useEffect } from "react";
import { useTheme } from "@/contexts/ThemeContext";

// Define the BlinkPayButton type on the window object for TypeScript
declare global {
  interface Window {
    BlinkPayButton?: {
      init: (options: any) => void;
    };
  }
}

const BlinkPayButton: React.FC = () => {
  const { theme } = useTheme();

  useEffect(() => {
    const scriptId = "blink-pay-button-script";

    const initBlinkWidget = () => {
      if (typeof window.BlinkPayButton !== "undefined") {
        window.BlinkPayButton.init({
          username: "destiny_smart",
          containerId: "blink-pay-button-container",
          themeMode: theme,
          language: "en",
          defaultAmount: 1000,
          supportedCurrencies: [
            { code: "sats", name: "sats", isCrypto: true },
            { code: "USD", name: "USD", isCrypto: false },
          ],
          debug: false,
        });
      }
    };

    let script = document.getElementById(scriptId) as HTMLScriptElement | null;
    if (!script) {
      script = document.createElement("script");
      script.id = scriptId;
      script.src =
        "https://blinkbitcoin.github.io/donation-button.blink.sv/js/blink-pay-button.js";
      script.async = true;
      script.onload = initBlinkWidget;
      document.body.appendChild(script);
    } else {
      initBlinkWidget();
    }
  }, [theme]);

  return <div id="blink-pay-button-container" />;
};

export default BlinkPayButton;