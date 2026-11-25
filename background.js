// Education and industry experience, newest first.
// kind: "education" | "industry" | "research"; current: true marks an ongoing position;
// upcoming: true marks a future one. Omit logo to show an empty node.
// An entry has either org + logo, or orgs: [{ name, logo, wordmark? }] for joint affiliations.
const background = [
  {
    kind: "industry",
    period: "Summer 2027",
    upcoming: true,
    org: "Google DeepMind",
    role: "Student Researcher",
    people: "Mentor: Jocelyn Shen",
    logo: "materials/gdm_logo.png"
  },
  {
    kind: "education",
    period: "2024 – present",
    current: true,
    org: "Carnegie Mellon University",
    role: "Ph.D. in Human-Computer Interaction, School of Computer Science",
    people: "Advisors: Hirokazu Shirado & Sauvik Das",
    logo: "materials/cmu_logo.svg"
  },
  {
    kind: "industry",
    period: "May – Aug 2026",
    orgs: [
      { name: "Microsoft Research AI Frontiers", logo: "materials/msr_logo.svg" },
      { name: "Microsoft AI", logo: "materials/mai_wordmark.png", wordmark: true }
    ],
    role: "Research Intern",
    people: "Mentors: Zachary Huang & Will Epperson"
  },
  {
    kind: "research",
    period: "2023",
    org: "University of California, Berkeley",
    role: "Research Intern, Berkeley AI Research (BAIR) & School of Information",
    people: "Advisors: Coye Cheshire & John Canny",
    logo: "materials/Berkeley_logo.svg"
  },
  {
    kind: "education",
    period: "2020 – 2024",
    org: "Tsinghua University",
    role: "B.S. in Computer Science, Department of Computer Science and Technology",
    people: "Advisors: Chun Yu & Yuanchun Shi",
    logo: "materials/tsinghua_logo.png"
  }
];
