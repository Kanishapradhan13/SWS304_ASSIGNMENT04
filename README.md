# SWS304_ASSIGNMENT04

## Lab 1 - Client-Side Prototype Pollution via Browser APIs

### Background
Some browser APIs read URL query parameters and assign them directly to JavaScript objects. If the code does not validate or sanitise keys before assignment, an attacker can inject the string __proto__ as a key, which JavaScript resolves as a reference to Object.prototype rather than a normal property name. This causes the injected property to appear on every object in the application, not just the one created from the URL parameters.

### Walkthrough

**Step 1** — Explore the Application and Find the Vulnerable JS Code
Open the lab using the PortSwigger link and log into your account if prompted. Once the lab loads, open the browser Developer Tools by pressing F12 and navigate to the Sources tab. You are looking for JavaScript files that iterate over URL query parameters and assign them to an object. The typical vulnerable pattern looks something like a loop that calls URLSearchParams to read each key-value pair and then sets those keys directly on an object using bracket notation — for example, obj[key] = value — without any check on what the key actually is.
Once you spot this pattern, make a note of the file name and line number. This is the pollution source — the place where attacker-controlled input (the URL) is written into a JavaScript object without validation.

**Step 2** — Verify the Pollution in the Console
With DevTools still open, switch to the Console tab. Append the following to the current page URL and reload:
```
?__proto__[testprop]=polluted
```

After the page reloads, type the following in the Console and press Enter:

```
Object.prototype.testprop
```

If the output is the string 'polluted', the prototype has been successfully contaminated. This confirms that the application takes whatever key you put inside __proto__[...] and writes it as a property directly on Object.prototype. Every object in the JavaScript runtime now inherits this property because they all trace back to Object.prototype at the top of the prototype chain.

**Step 3** — Identify and Craft the Final Exploit Payload
Now look at the rest of the JavaScript code in the Sources tab. Find the section that acts as the sink — the part of the code that reads a property from an object and does something dangerous with it, such as passing it to eval(), setting innerHTML, calling document.write(), or anything else that executes arbitrary code. The property name it reads is what you need to pollute.

Once you have identified the sink property, craft your final payload URL. For example, if the sink reads a property called transport_url and passes it to a script or eval call, your payload would be:
```
?__proto__[transport_url]=data:,alert(1)
```

Append this to the lab URL, reload the page, and the injected code should execute. When the lab's success condition is triggered (usually an alert or a call to print()), the lab will display a 'Congratulations' banner indicating it is solved.

### Summary
This lab demonstrated a client-side prototype pollution vulnerability where URL parameters were assigned to a JavaScript object without any key validation. Because the string __proto__ is treated by JavaScript as a reference to the prototype of the object rather than a literal key, writing to obj["__proto__"][x] is equivalent to writing to Object.prototype.x. This causes the injected property to propagate to every object in the browser's JavaScript runtime. In a real-world scenario, this can lead to script execution, privilege escalation on the client side, or bypassing security checks that rely on property lookups — all triggered simply by sharing a crafted URL with a victim.

### Questions — Lab 1

#### Question 1.1

Q: Why does adding ?__proto__[x]=y to the URL cause Object.prototype to be modified — and not just the single object created from the URL parameters?

In JavaScript, every object has an internal link to a prototype object, and that chain terminates at Object.prototype. When you write someObject["__proto__"] in bracket notation, JavaScript does not create a property called __proto__ on someObject. Instead, the engine interprets __proto__ as a special accessor that points to the object's own prototype. So when the vulnerable code does obj[key] = value and key happens to be the string "__proto__", it is not adding a key to obj. It is instead accessing obj's prototype — which for plain objects is Object.prototype — and adding the key x with value y directly there.

Because all JavaScript objects ultimately inherit from Object.prototype, this single modification is immediately visible on every object in the runtime. If you check ({}).x after the pollution, it will return y — not because that plain object has an x property of its own, but because it looks up the chain and finds it on Object.prototype. The URL parameter just happened to be the vehicle that delivered the key string "__proto__" into the vulnerable assignment code.

### Question 1.2

Q: Name ONE defence a developer could add to prevent this attack, and explain in 2 sentences how it would stop the pollution.

The most effective single fix is to use Object.create(null) when creating the object that will receive URL parameters, instead of using a plain object literal like {}. An object created with Object.create(null) has no prototype at all — its internal [[Prototype]] is null — so writing obj["__proto__"] simply creates a harmless string-keyed property named __proto__ on that empty object rather than traversing up the chain to Object.prototype. The pollution has nowhere to go.
