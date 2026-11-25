import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { A11yMenu, applyStoredA11y } from "./components/A11yMenu";
import "./styles.css";

// לפני הציור הראשון, כדי שלא יהיה הבזק של הערכה הרגילה.
applyStoredA11y();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <a className="skip-link" href="#main">דילוג לתוכן</a>
    <App />
    <A11yMenu />
  </StrictMode>,
);
