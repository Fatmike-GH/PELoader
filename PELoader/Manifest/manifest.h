// If the target application requires a manifest specifying specific module versions, it can be added here as a workaround. 
// Note: The linker option "Linker -> Manifest File -> Generate Manifest" must be enabled for this to work.
//
// In a real-world scenario, where the PE loader loads the target from a section or from embedded resources,
// the manifest should be extracted from the target exe and added to the pe loader as a resource.
//
// For this conceptual PE loader, however, this simplified approach is sufficient.
//
// Many target applications i tested depended on version 6.0.0.0 of comctl32.dll, as certain UI functions are only available in this version.
// Therefore, to ensure compatibility with such targets, version 6.0.0.0 of comctl32.dll will be included in the embedded manifest of this loader:

#pragma comment(linker,"\"/manifestdependency:type='win32' \ name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \ processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")