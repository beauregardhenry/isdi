"""The take-home copy of the consultation report in Spanish.

One table, keyed by the English wording used in the model (questions, risk
names and descriptions), the answer choices and the report template. What
the client or staff typed (notes, account names, app names) is never
translated. tests/test_consultation_i18n.py renders a fully filled-in record
in Spanish and fails on any English left untranslated.

The translation has not yet been reviewed by a native speaker who works with
clients: review it before relying on it. Conventions: "person of concern" is
"la persona que le preocupa", "the client" is "la persona atendida" (both
gender-neutral), and the client is addressed as "usted".
"""

import re
from typing import Callable

ES = {
    # --- the report page ---------------------------------------------------
    "Notes": "Notas",
    "Print this page, or save it as PDF from the browser's print dialog.": (
        "Imprima esta página o guárdela como PDF desde el cuadro de impresión "
        "del navegador."
    ),
    "This copy leaves out the client's name, the consultant's notes and the names of the clinic and of the tool.": (
        "Esta copia no incluye el nombre de la persona atendida, las notas de "
        "quien hizo la consulta ni los nombres de la clínica y de la "
        "herramienta."
    ),
    "Summary": "Resumen",
    "Questionnaire": "Cuestionario",
    "Devices": "Dispositivos",
    "Accounts": "Cuentas",
    "Unnamed device": "Dispositivo sin nombre",
    "No devices recorded.": "No se registraron dispositivos.",
    "No accounts checked.": "No se revisaron cuentas.",
    "None found.": "No se encontró ninguno.",
    "What the client said": "Lo que dijo la persona atendida",
    "None": "Ninguno",
    "Marked complete.": "Marcado como completo.",
    "Not answered": "Sin respuesta",
    "Device": "Dispositivo",
    "Account": "Cuenta",
    "Type": "Tipo",
    "Not recorded": "No registrado",
    "added by hand, not scanned": "agregado a mano, no escaneado",
    "Manufacturer and model": "Fabricante y modelo",
    "Operating system version": "Versión del sistema operativo",
    "Rooted or jailbroken": "Con root o jailbreak",
    "Signs found": "Se encontraron señales",
    "No signs found": "No se encontraron señales",
    "App id": "Identificador de la aplicación",
    "Flags": "Marcas",
    "Installed": "Instalada",
    "Version": "Versión",
    "Screenshot": "Captura de pantalla",
    "taken": "tomada el",
    # Questionnaire sections
    "Accounts and passwords": "Cuentas y contraseñas",
    "Sharing": "Cosas compartidas",
    "Smart home devices": "Dispositivos del hogar inteligente",
    "Children's devices": "Dispositivos de los hijos",
    "Legal proceedings": "Procesos legales",
    # Account sections
    "Devices and logins": "Dispositivos e inicios de sesión",
    "Password": "Contraseña",
    "Recovery settings": "Opciones de recuperación",
    "Two-factor authentication": "Verificación en dos pasos",
    "Security questions": "Preguntas de seguridad",
    # --- answer choices (consultation/choices.py) --------------------------
    "Yes": "Sí",
    "No": "No",
    "Unsure": "No lo sé",
    "Me": "Yo",
    "Person of concern": "La persona que le preocupa",
    "Someone else": "Otra persona",
    "Online notes": "Notas en línea",
    "Paper notes": "Notas en papel",
    "Password manager": "Administrador de contraseñas",
    "Take a photo of it": "Le tomo una foto",
    "Other": "Otro",
    "No specific method": "Ningún método en particular",
    "Restraining order": "Orden de protección",
    "Divorce or other family court": "Divorcio u otro caso de familia",
    "Criminal case": "Caso penal",
    "Android": "Android",
    "iOS": "iOS",
    "Phone": "Teléfono",
    "Email": "Correo electrónico",
    "Authenticator App": "Aplicación de autenticación",
    "Trusted Device": "Dispositivo de confianza",
    # --- questions (consultation/model.py) ---------------------------------
    "Do you live with the person of concern?": (
        "¿Vive con la persona que le preocupa?"
    ),
    "Did the person of concern purchase and/or set up any of your devices?": (
        "¿La persona que le preocupa compró o configuró alguno de sus " "dispositivos?"
    ),
    "Which devices did the person of concern purchase and/or set up?": (
        "¿Qué dispositivos compró o configuró la persona que le preocupa?"
    ),
    "Has the person of concern had physical access to your devices at any point in time?": (
        "¿La persona que le preocupa ha tenido sus dispositivos en sus manos "
        "en algún momento?"
    ),
    "To which devices has the person of concern had physical access?": (
        "¿Qué dispositivos ha tenido en sus manos la persona que le preocupa?"
    ),
    "Can the person of concern unlock any of these devices with PIN, password, or biometrics?": (
        "¿Puede la persona que le preocupa desbloquear alguno de estos "
        "dispositivos con un PIN, una contraseña, la huella o la cara?"
    ),
    "How do you remember your passwords?": "¿Cómo recuerda sus contraseñas?",
    "Please provide more details on how you remember your passwords.": (
        "Dé más detalles sobre cómo recuerda sus contraseñas."
    ),
    "Do you believe the person of concern knows, or could guess, any of your passwords?": (
        "¿Cree que la persona que le preocupa conoce, o podría adivinar, "
        "alguna de sus contraseñas?"
    ),
    "Which passwords do you believe are compromised, and why?": (
        "¿Qué contraseñas cree que están comprometidas, y por qué?"
    ),
    "Do you share a phone plan with the person of concern?": (
        "¿Comparte un plan de teléfono con la persona que le preocupa?"
    ),
    "If you share a phone plan, who is the family 'head' or plan administrator?": (
        "Si comparte un plan de teléfono, ¿quién es el titular o "
        "administrador del plan?"
    ),
    "Do you share any accounts with the person of concern?": (
        "¿Comparte alguna cuenta con la persona que le preocupa?"
    ),
    "Which accounts are shared with the person of concern?": (
        "¿Qué cuentas comparte con la persona que le preocupa?"
    ),
    "Do you have any smart home devices?": (
        "¿Tiene dispositivos del hogar inteligente?"
    ),
    "Who installed and set up your smart home devices?": (
        "¿Quién instaló y configuró sus dispositivos del hogar inteligente?"
    ),
    "Did the person of concern ever have physical access to the devices?": (
        "¿La persona que le preocupa tuvo alguna vez acceso físico a esos "
        "dispositivos?"
    ),
    "Do you share any smart home accounts with the person of concern?": (
        "¿Comparte alguna cuenta del hogar inteligente con la persona que le "
        "preocupa?"
    ),
    "Can the person of concern access any of the smart home devices via their own smart home account?": (
        "¿Puede la persona que le preocupa usar alguno de esos dispositivos "
        "desde su propia cuenta del hogar inteligente?"
    ),
    "If you have children, do they have electronic devices?": (
        "Si tiene hijos, ¿tienen dispositivos electrónicos?"
    ),
    "Has the person of concern had physical access to any of the child(ren)'s devices?": (
        "¿La persona que le preocupa ha tenido en sus manos algún dispositivo "
        "de sus hijos?"
    ),
    "Does the person of concern pay for the child(ren)'s phone plan?": (
        "¿La persona que le preocupa paga el plan de teléfono de sus hijos?"
    ),
    "Do you have any ongoing or upcoming legal cases?": (
        "¿Tiene algún caso legal en curso o próximo?"
    ),
    "Do you see any unrecognized devices that are logged into this account?": (
        "¿Ve algún dispositivo que no reconoce con la sesión iniciada en esta "
        "cuenta?"
    ),
    "Which devices do you not recognize?": "¿Qué dispositivos no reconoce?",
    "In the login history, do you see any suspicious logins?": (
        "En el historial de inicios de sesión, ¿ve alguno sospechoso?"
    ),
    "Which logins are suspicious, and why?": (
        "¿Qué inicios de sesión son sospechosos, y por qué?"
    ),
    "When did you last update this password (approximately)?": (
        "¿Cuándo cambió esta contraseña por última vez (aproximadamente)?"
    ),
    "Does the person of concern know the password for this account?": (
        "¿La persona que le preocupa conoce la contraseña de esta cuenta?"
    ),
    "Do you believe the person of concern could guess the password?": (
        "¿Cree que la persona que le preocupa podría adivinar la contraseña?"
    ),
    "Do you log into this account using a federated login (e.g., Google, Facebook, Apple)?": (
        "¿Entra a esta cuenta con otra cuenta (por ejemplo, con Google, "
        "Facebook o Apple)?"
    ),
    "What other account do you use to log in?": ("¿Qué otra cuenta usa para entrar?"),
    "Do you believe the person of concern has access to the federated account?": (
        "¿Cree que la persona que le preocupa tiene acceso a esa otra cuenta?"
    ),
    "Is there a recovery phone number set for this account?": (
        "¿Tiene esta cuenta un número de teléfono de recuperación?"
    ),
    "What is the recovery phone number?": (
        "¿Cuál es el número de teléfono de recuperación?"
    ),
    "Do you believe the person of concern has access to the recovery phone number?": (
        "¿Cree que la persona que le preocupa tiene acceso a ese número de "
        "recuperación?"
    ),
    "Is there a recovery email address set for this account?": (
        "¿Tiene esta cuenta un correo electrónico de recuperación?"
    ),
    "What is the recovery email address?": (
        "¿Cuál es el correo electrónico de recuperación?"
    ),
    "Do you believe the person of concern has access to this recovery email address?": (
        "¿Cree que la persona que le preocupa tiene acceso a ese correo de "
        "recuperación?"
    ),
    "Is two-factor authentication enabled for this account?": (
        "¿Está activada la verificación en dos pasos en esta cuenta?"
    ),
    "What type of two-factor authentication is used?": (
        "¿Qué tipo de verificación en dos pasos se usa?"
    ),
    "Which phone/email/app is set as the second factor?": (
        "¿Qué teléfono, correo o aplicación se usa como segundo paso?"
    ),
    "Do you believe the person of concern has access to this second factor?": (
        "¿Cree que la persona que le preocupa tiene acceso a ese segundo paso?"
    ),
    "Does the account use security questions?": (
        "¿Usa la cuenta preguntas de seguridad?"
    ),
    "Do you believe the person of concern knows the answer to any of these questions?": (
        "¿Cree que la persona que le preocupa sabe la respuesta a alguna de "
        "esas preguntas?"
    ),
    "Which questions might they be able to answer?": (
        "¿Qué preguntas podría contestar?"
    ),
    "Is any information being leaked to the person of concern through this app?": (
        "¿Esta aplicación le está pasando información a la persona que le " "preocupa?"
    ),
    "If yes, please describe.": "Si es así, descríbalo.",
    "Did you know this app was installed?": (
        "¿Sabía que esta aplicación estaba instalada?"
    ),
    "Did you install this app?": "¿Instaló usted esta aplicación?",
    "Did the person of concern coerce you into installing this app?": (
        "¿La persona que le preocupa le obligó a instalar esta aplicación?"
    ),
    # --- risks (consultation/model.py) -------------------------------------
    "Physical access to devices": "Acceso físico a los dispositivos",
    "A person with physical access to devices might be able to install apps, adjust device configurations, and access or manipulate accounts logged in on that device.": (
        "Alguien que tiene los dispositivos en sus manos podría instalar "
        "aplicaciones, cambiar su configuración y entrar a las cuentas con "
        "sesión iniciada en ellos, o modificarlas."
    ),
    # The same, with a sentence the model adds when the person can unlock
    # the device (TAQDevices).
    "A person with physical access to devices might be able to install apps, adjust device configurations, and access or manipulate accounts logged in on that device. They can also unlock the device with a PIN, password, or biometrics, which would allow them to access all data on the device.": (
        "Alguien que tiene los dispositivos en sus manos podría instalar "
        "aplicaciones, cambiar su configuración y entrar a las cuentas con "
        "sesión iniciada en ellos, o modificarlas. También puede "
        "desbloquearlos con un PIN, una contraseña, la huella o la cara, lo "
        "que le daría acceso a todos sus datos."
    ),
    "Password compromise": "Contraseña comprometida",
    "Someone who knows account passwords may be able to access and/or manipulate those accounts.": (
        "Alguien que conoce las contraseñas de las cuentas podría entrar a "
        "esas cuentas o modificarlas."
    ),
    "Shared phone plan": "Plan de teléfono compartido",
    "A shared phone plan may leak a variety of information, possibly including call history, message history (but not message content), contacts, and sometimes location. The account administrator of the client's phone plan has even more privileged access to this information.": (
        "Un plan de teléfono compartido puede revelar mucha información: el "
        "historial de llamadas, el historial de mensajes (pero no su "
        "contenido), los contactos y a veces la ubicación. Quien administra "
        "el plan de la persona atendida tiene todavía más acceso a esa "
        "información."
    ),
    "Shared accounts": "Cuentas compartidas",
    "The client has shared accounts with the person of concern. Any information on those accounts can be assumed to be known by the person of concern.": (
        "La persona atendida comparte cuentas con la persona que le preocupa. "
        "Hay que suponer que la persona que le preocupa conoce toda la "
        "información de esas cuentas."
    ),
    "Physical access to smart home devices": (
        "Acceso físico a los dispositivos del hogar inteligente"
    ),
    "With physical access to smart home devices, someone could (1) learn private information, for example by querying a smart speaker, or (2) reconfigure the devices to share information or allow remote control. Someone who initially set up the devices would have even more power to configure as they wish.": (
        "Con acceso físico a los dispositivos del hogar inteligente, alguien "
        "podría (1) conocer información privada, por ejemplo preguntándole a "
        "un altavoz inteligente, o (2) cambiar su configuración para "
        "compartir información o controlarlos a distancia. Quien los "
        "configuró al principio tendría todavía más control sobre ellos."
    ),
    "With physical access to smart home devices, someone could (1) learn private information, for example by querying a smart speaker, or (2) reconfigure the devices to share information or allow remote control.": (
        "Con acceso físico a los dispositivos del hogar inteligente, alguien "
        "podría (1) conocer información privada, por ejemplo preguntándole a "
        "un altavoz inteligente, o (2) cambiar su configuración para "
        "compartir información o controlarlos a distancia."
    ),
    "Online access to smart home devices": (
        "Acceso en línea a los dispositivos del hogar inteligente"
    ),
    "Someone with online access to a smart home device might be able to gather data (e.g., viewing video recordings or voice commands used) or manipulate the device state (e.g., turning a light off or locking a smart lock.)": (
        "Alguien con acceso en línea a un dispositivo del hogar inteligente "
        "podría reunir datos (por ejemplo, ver grabaciones de video o los "
        "comandos de voz usados) o cambiar su estado (por ejemplo, apagar una "
        "luz o cerrar una cerradura inteligente)."
    ),
    "Physical access to children's devices": (
        "Acceso físico a los dispositivos de los hijos"
    ),
    "A person with physical access to children's devices might be able to install apps, adjust device configurations, and access or manipulate accounts logged in on that device. These changes could allow monitoring of the parent, for example by tracking the children's location when they are with their parent.": (
        "Alguien que tiene en sus manos los dispositivos de los hijos podría "
        "instalar aplicaciones, cambiar su configuración y entrar a las "
        "cuentas con sesión iniciada en ellos, o modificarlas. Esos cambios "
        "podrían servir para vigilar a la madre o al padre, por ejemplo "
        "siguiendo la ubicación de los hijos cuando están con esa persona."
    ),
    "Shared phone plan (child)": "Plan de teléfono compartido (hijos)",
    "A shared phone plan may leak a variety of information, possibly including call history, message history (but not message content), contacts, and sometimes location. This could include information about the parent, such as their phone number and location when with the children. The plan administrator has even more privileged access to this information.": (
        "Un plan de teléfono compartido puede revelar mucha información: el "
        "historial de llamadas, el historial de mensajes (pero no su "
        "contenido), los contactos y a veces la ubicación. Eso podría incluir "
        "información sobre la madre o el padre, como su número de teléfono y "
        "su ubicación cuando está con los hijos. Quien administra el plan "
        "tiene todavía más acceso a esa información."
    ),
    "Unrecognized devices": "Dispositivos no reconocidos",
    "There are unrecognized devices currently logged into this account.": (
        "Hay dispositivos no reconocidos con la sesión iniciada en esta " "cuenta."
    ),
    "Suspicious logins": "Inicios de sesión sospechosos",
    "There are suspicious logins to this account that do not appear to have come from the client.": (
        "Hay inicios de sesión sospechosos en esta cuenta que no parecen "
        "venir de la persona atendida."
    ),
    "Knowing the password to this account could enable the person of concern to log in. (Note: If two-factor authentication is enabled, they would still need to bypass the second factor.)": (
        "Conocer la contraseña de esta cuenta podría permitirle a la persona "
        "que le preocupa entrar. (Si la verificación en dos pasos está "
        "activada, todavía tendría que pasar el segundo paso.)"
    ),
    "Potential password compromise": "Posible contraseña comprometida",
    "The client believes the person of concern could guess the password for this account. If they guess correctly, it would enable them to log in. (Note: If two-factor authentication is enabled, they would still need to bypass the second factor.)": (
        "La persona atendida cree que la persona que le preocupa podría "
        "adivinar la contraseña de esta cuenta. Si la adivina, podría entrar. "
        "(Si la verificación en dos pasos está activada, todavía tendría que "
        "pasar el segundo paso.)"
    ),
    "Compromised federated account": "Cuenta de inicio de sesión comprometida",
    "By compromising the federated account, the person of concern could log into this account without needing to know the password.": (
        "Si la persona que le preocupa tiene acceso a la cuenta con la que se "
        "entra a esta, podría entrar sin conocer la contraseña."
    ),
    "Compromised recovery information": "Datos de recuperación comprometidos",
    "With access to the recovery contact information, someone can access an account without knowing the password using the 'Forgot password' option.": (
        "Con acceso al teléfono o correo de recuperación, alguien puede entrar "
        "a una cuenta sin conocer la contraseña, con la opción «¿Olvidó su "
        "contraseña?»."
    ),
    "Compromised second factor": "Segundo paso comprometido",
    "If someone has access to the second authentication factor, they only need the account password to log into the account. They could also intercept and delete login notifications.": (
        "Si alguien tiene acceso al segundo paso de verificación, solo "
        "necesita la contraseña para entrar a la cuenta. También podría ver y "
        "borrar los avisos de inicio de sesión."
    ),
    "Two-factor authentication disabled": "Verificación en dos pasos desactivada",
    "Without two-factor authentication, others only need the account password to log in.": (
        "Sin la verificación en dos pasos, otras personas solo necesitan la "
        "contraseña para entrar."
    ),
    "Guessable security questions": "Preguntas de seguridad fáciles de adivinar",
    "The client believes the person of concern knows the answers to security questions, which could allow them an easy way to log into the account.": (
        "La persona atendida cree que la persona que le preocupa sabe las "
        "respuestas a las preguntas de seguridad, lo que le daría una manera "
        "fácil de entrar a la cuenta."
    ),
    "Use of security questions": "Uso de preguntas de seguridad",
    "The account allows login using security questions, which are not secure because they are easy to guess.": (
        "La cuenta permite entrar con preguntas de seguridad, que no son "
        "seguras porque son fáciles de adivinar."
    ),
    "App installed without permission": "Aplicación instalada sin permiso",
    "The client did not know this app was installed, indicating someone else installed it.": (
        "La persona atendida no sabía que esta aplicación estaba instalada, "
        "lo que indica que otra persona la instaló."
    ),
    "The client did not install this app, indicating someone else installed it.": (
        "La persona atendida no instaló esta aplicación, lo que indica que "
        "otra persona la instaló."
    ),
    "The client was coerced into installing this app.": (
        "La persona atendida fue obligada a instalar esta aplicación."
    ),
    "Data leakage": "Filtración de datos",
    "This app is sharing data with the person of concern.": (
        "Esta aplicación comparte datos con la persona que le preocupa."
    ),
    "Spyware application": "Aplicación espía",
    "This app is designed for covert surveillance.": (
        "Esta aplicación está hecha para vigilar a escondidas."
    ),
    "Potential spyware application": "Posible aplicación espía",
    "This app may be a spyware application based on its title and description.": (
        "Por su nombre y su descripción, esta aplicación podría ser una "
        "aplicación espía."
    ),
    "Evidence of jailbreaking": "Señales de jailbreak",
    "The device may be jailbroken, giving the person of concern nearly unbounded access to the device and the client's activity on the device.": (
        "Puede que el dispositivo tenga jailbreak, lo que le daría a la "
        "persona que le preocupa un acceso casi ilimitado al dispositivo y a "
        "lo que la persona atendida hace en él."
    ),
}

# Risks whose wording is built around a name (consultation/model.py).
_APP_RISK = re.compile(r"^Risk from app: (.*)$", re.S)
_APP_RISKS_FOUND = re.compile(r"^Risks identified: (.*)\.$", re.S)


def translator(lang: str, strict: bool = False) -> Callable[[object], object]:
    """t(text) in the given language. English, None and "" pass through.
    With strict=True (tests), text with no translation raises KeyError."""

    def t(text):
        if lang != "es" or not isinstance(text, str) or not text:
            return text
        if text in ES:
            return ES[text]
        m = _APP_RISK.match(text)
        if m:
            return f"Riesgo de la aplicación: {m.group(1)}"
        m = _APP_RISKS_FOUND.match(text)
        if m:
            names = [t(n.strip()) for n in m.group(1).split(",")]
            return f"Riesgos encontrados: {', '.join(names)}."
        if strict:
            raise KeyError(text)
        return text

    return t
